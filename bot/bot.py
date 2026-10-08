"""
Discord bot for the Luraph deobfuscator — prefix commands, auto-detect.

Usage (prefix is `.lph`):
    .lph <attachment>              smart: full -> strings -> trace fallback
    .lph <url>                     same, but download from an http(s) link
    .lph                           then paste the script on the next line(s)
    .lph full <attachment|url>     force full devirtualization only
    .lph trace <attachment|url>    behavior-trace only
    .lph strings <attachment|url>  strings dump + trace fallback
    .lph detect <attachment|url>   scan the header only
    .lph help
    .lph ping
    .lph stats

The version is auto-detected from the Luraph banner.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
import discord

from scanner import scan
from dispatcher import describe_dispatch

# ---------------------------------------------------------------- config

JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/jobs"))
IN = JOBS_DIR / "in"
OUT = JOBS_DIR / "out"
IN.mkdir(parents=True, exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)

PREFIX = os.environ.get("PREFIX", ".lph")

JOB_TIMEOUT = int(os.environ.get("JOB_TIMEOUT", 600))
STARTED_AT = time.time()

ALLOWED_SUFFIXES = (".lua", ".luau", ".lph", ".txt")
FORBIDDEN_SUFFIXES = (
    ".exe", ".dll", ".so", ".dylib",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".py", ".pyc", ".bat", ".cmd", ".ps1", ".sh", ".js",
    ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".mp3", ".wav",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)

MAX_QUEUE_DEPTH = 32

URL_TIMEOUT = 120.0
URL_MAX_REDIRECTS = 5
ALLOWED_SCHEMES = {"http", "https"}

USER_COOLDOWN = 10.0
_last_run: dict[int, float] = {}

# strip comment lines containing "oxy" anywhere (dsc.gg/oxyenv, oxygen, ...)
_CLEAN_RE = re.compile(r"^\s*--.*?oxy", re.IGNORECASE)

# ---------------------------------------------------------------- channel lock

_OPEN_TOKENS = {"", "any", "all", "*", "none", "null", "0"}


def _parse_channel_lock(raw: str | None) -> set[int] | None:
    if not raw:
        return None
    s = raw.strip().lower()
    if s in _OPEN_TOKENS:
        return None
    ids: set[int] = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part or part.lower() in _OPEN_TOKENS:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            print(f"[bot] ignoring bad ALLOWED_CHANNEL_ID entry: {part!r}", flush=True)
    return ids or None


ALLOWED_CHANNELS: set[int] | None = _parse_channel_lock(
    os.environ.get("ALLOWED_CHANNEL_ID")
)

# ---------------------------------------------------------------- client

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)


# ---------------------------------------------------------------- helpers

def _queue_depth() -> int:
    try:
        return sum(1 for _ in IN.glob("*.json"))
    except OSError:
        return 0


def _channel_ok(message: discord.Message) -> bool:
    if ALLOWED_CHANNELS is None:
        return True
    return message.channel.id in ALLOWED_CHANNELS


def _bad_ext(name: str) -> bool:
    low = name.lower()
    if low.endswith(FORBIDDEN_SUFFIXES):
        return True
    if "." not in low:
        return False
    return not low.endswith(ALLOWED_SUFFIXES)


def _scan_bytes(data: bytes) -> dict:
    tmp = IN / f".scan-{uuid.uuid4().hex}.luau"
    try:
        tmp.write_bytes(data)
        return scan(tmp)
    finally:
        tmp.unlink(missing_ok=True)


def _scan_summary(info: dict) -> str:
    if not info.get("found"):
        return "no Luraph banner (will let the tool auto-detect)"
    return f"Luraph v{info['version']}"


def _cooldown_left(user_id: int) -> float:
    last = _last_run.get(user_id, 0.0)
    return max(0.0, USER_COOLDOWN - (time.time() - last))


def _human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def _mode_label(mode: str) -> str:
    return {
        "smart": "smart (full → strings → trace)",
        "full": "full devirtualization",
        "trace": "behavior trace only",
        "strings": "strings dump + trace fallback",
    }.get(mode, mode)


def _clean_output(text: str) -> str:
    """Remove any comment line containing 'oxy' (case-insensitive)."""
    lines = text.split("\n")
    kept = [l for l in lines if not _CLEAN_RE.search(l)]
    removed = len(lines) - len(kept)
    if removed:
        print(f"[bot] stripped {removed} oxy comment line(s)", flush=True)
    return "\n".join(kept)


# ---------------------------------------------------------------- SSRF

def _bad_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _safe_url(url: str) -> tuple[bool, str]:
    try:
        p = urlparse(url)
    except Exception:
        return False, "malformed URL"

    if p.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"scheme `{p.scheme}` not allowed (use http or https)"

    host = p.hostname
    if not host:
        return False, "URL has no host"

    try:
        ip = ipaddress.ip_address(host)
        if _bad_ip(ip):
            return False, f"refusing to fetch from `{ip}`"
        return True, ""
    except ValueError:
        pass

    port = p.port or (443 if p.scheme.lower() == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False, f"cannot resolve `{host}`"

    for _, _, _, _, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _bad_ip(ip):
            return False, f"`{host}` resolves to `{ip}` (private/reserved)"
    return True, ""


async def _fetch_url(url: str) -> tuple[bytes | None, str, str]:
    timeout = aiohttp.ClientTimeout(total=URL_TIMEOUT, connect=10)
    headers = {"User-Agent": "luraph-bot/1.0"}
    current = url

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for _ in range(URL_MAX_REDIRECTS + 1):
            ok, err = _safe_url(current)
            if not ok:
                return None, err, current
            try:
                async with session.get(current, allow_redirects=False) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location")
                        if not loc:
                            return None, "redirect without Location header", current
                        current = urljoin(current, loc)
                        continue

                    if resp.status != 200:
                        return None, f"HTTP {resp.status}", current

                    body = await resp.read()
                    return body, "", current
            except aiohttp.ClientError as e:
                return None, f"network error: {e}", current
            except asyncio.TimeoutError:
                return None, "download timed out", current

        return None, f"too many redirects (>{URL_MAX_REDIRECTS})", current


def _looks_like_url(s: str) -> bool:
    low = s.lstrip().lower()
    return low.startswith("http://") or low.startswith("https://")


# ---------------------------------------------------------------- inline source

BANNER_HINT = re.compile(
    r"^\s*--?\s*.*?This\s+file\s+was\s+protected\s+using\s+Luraph",
    re.IGNORECASE | re.MULTILINE,
)
CODE_FENCE_OPEN = re.compile(r"^```[A-Za-z0-9_+-]*\s*$")
CODE_FENCE_ANY = re.compile(r"^```\s*$")


def _strip_code_fences(text: str) -> str:
    lines = text.split("\n")
    while lines and CODE_FENCE_OPEN.match(lines[0]):
        lines = lines[1:]
    while lines and CODE_FENCE_ANY.match(lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines)


def _extract_inline_source(text: str) -> str | None:
    if not text:
        return None

    stripped = _strip_code_fences(text.strip())

    m = BANNER_HINT.search(stripped)
    if m:
        body = stripped[m.start():]
    else:
        body = stripped

    body = _strip_code_fences(body).rstrip()
    if not body:
        return None

    head = body.lstrip()
    if not (
        "This file was protected using Luraph" in body
        or head.startswith("return(function")
        or head.startswith("return function")
        or head.startswith("return (function")
        or head.startswith("local ")
    ):
        return None

    return body


# ---------------------------------------------------------------- source extraction

class SourceError(Exception):
    pass


async def _resolve_source(
    message: discord.Message,
    source_text: str | None,
) -> tuple[bytes, str]:
    # 1) attachment
    if message.attachments:
        att = message.attachments[0]
        if _bad_ext(att.filename):
            raise SourceError(
                f"refusing `{att.filename}` — looks like a binary/archive.\n"
                f"rename it to end in `.lua`, `.luau`, `.lph` or `.txt`, "
                f"then re-send."
            )
        try:
            data = await att.read()
        except discord.HTTPException as e:
            raise SourceError(f"failed to download the attachment: `{e}`") from e

        name = att.filename
        low = name.lower()
        if "." not in low or not low.endswith(ALLOWED_SUFFIXES):
            stem = name.rsplit(".", 1)[0] if "." in name else name
            name = (stem or "upload") + ".luau"
        return data, name

    # 2) URL
    if source_text and _looks_like_url(source_text):
        first_token = source_text.split()[0]
        ok, err = _safe_url(first_token)
        if not ok:
            raise SourceError(err)
        data, err, final_url = await _fetch_url(first_token)
        if data is None:
            raise SourceError(err)
        parsed = urlparse(final_url)
        tail = (parsed.path.rsplit("/", 1)[-1] or "downloaded").strip() or "downloaded"
        low = tail.lower()
        if low.endswith(FORBIDDEN_SUFFIXES):
            raise SourceError(f"refusing `{tail}` (forbidden extension)")
        if not low.endswith(ALLOWED_SUFFIXES):
            stem = tail.rsplit(".", 1)[0] if "." in tail else tail
            tail = (stem or "downloaded") + ".luau"
        return data, tail

    # 3) inline pasted code
    if source_text:
        body = _extract_inline_source(source_text)
        if body:
            return body.encode("utf-8", "replace"), "pasted.luau"

    raise SourceError(
        "attach a file, paste a direct `http(s)://` link, "
        "or paste the script text itself (in a code block or raw)."
    )


# ---------------------------------------------------------------- job runner

def _force_luau_name(original_name: str) -> str:
    """Given any name, produce `<stem>.deobf.luau`."""
    stem = Path(original_name).stem or "output"
    if not stem:
        stem = "output"
    stem = stem.rstrip(".")
    return f"{stem}.deobf.luau"


async def _run_job(
    message: discord.Message,
    data: bytes,
    original_name: str,
    mode: str,
) -> None:
    info = _scan_bytes(data)
    resolved_engine = info.get("engine") if info.get("found") else None

    note = describe_dispatch(info, None)
    header_line = info.get("banner") or "(no banner)"

    status = (
        f"**Detected:** {_scan_summary(info)}\n"
        f"**Banner:** `{header_line[:200]}`\n"
        f"**Input:** `{original_name}` ({_human_size(len(data))})\n"
        f"**Mode:** {_mode_label(mode)}\n"
        f"**Dispatch:** {note}"
    )
    await message.reply(status, mention_author=False)

    job_id = uuid.uuid4().hex
    src = IN / f"{job_id}.luau"
    src.write_bytes(data)

    job = {
        "id": job_id,
        "input": str(src),
        "engine": resolved_engine,
        "mode": mode,
        "original_name": original_name,
    }
    (IN / f"{job_id}.json").write_text(json.dumps(job))

    result_path = OUT / f"{job_id}.json"
    deadline = time.time() + JOB_TIMEOUT

    try:
        while time.time() < deadline:
            if result_path.exists():
                break
            await asyncio.sleep(1)
        else:
            await message.reply(
                f"timed out after {JOB_TIMEOUT}s. The script may be too large "
                f"or hit an unsupported VM layout.",
                mention_author=False,
            )
            return

        try:
            res = json.loads(result_path.read_text())
        except Exception as e:
            await message.reply(f"bad result file: `{e}`", mention_author=False)
            return

        if res.get("error"):
            body = res["error"][:1600]
            attempts = res.get("attempts")
            hint = ""
            if attempts:
                hint = f"\n\nmodes tried: {', '.join(attempts)} — all failed."
            if mode == "smart":
                hint += (
                    f"\n\nTip: try `{PREFIX} trace <same source>` to force a "
                    f"pure behavior trace with no devirt attempt."
                )
            await message.reply(
                f"deobfuscation failed:\n```\n{body}\n```{hint}",
                mention_author=False,
            )
            return

        out_path = Path(res["output"])
        raw = out_path.read_bytes()
        out_path.unlink(missing_ok=True)

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
        text = _clean_output(text)
        payload = text.encode("utf-8")

        name = _force_luau_name(original_name)

        elapsed = res.get("elapsed", 0)
        extra = ""
        rinfo = res.get("scan") or {}
        if rinfo.get("found"):
            extra = f" · Luraph v{rinfo['version']}"
        used = res.get("mode_used")
        if used and used != mode:
            extra += f" · used `{used}`"

        await message.reply(
            content=f"done in {elapsed:.1f}s — {_human_size(len(payload))}{extra}",
            file=discord.File(io.BytesIO(payload), filename=name),
            mention_author=False,
        )
    finally:
        src.unlink(missing_ok=True)
        (IN / f"{job_id}.json").unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)


# ---------------------------------------------------------------- command handling

HELP_TEXT = (
    f"**luraph deobfuscator**\n"
    f"`{PREFIX} <attachment>` — smart run (tries full → strings → trace)\n"
    f"`{PREFIX} <url>` — same, but download from an http(s) link\n"
    f"`{PREFIX}` then paste the script on the next line(s) — deobfuscate pasted text\n"
    f"`{PREFIX} full <attachment|url>` — force full devirtualization only\n"
    f"`{PREFIX} trace <attachment|url>` — behavior trace only\n"
    f"`{PREFIX} strings <attachment|url>` — strings dump + trace fallback\n"
    f"`{PREFIX} detect <attachment|url|text>` — scan the header only\n"
    f"`{PREFIX} help` — this message\n"
    f"`{PREFIX} ping` — health check\n"
    f"`{PREFIX} stats` — queue depth and uptime\n\n"
    f"accepted extensions: `{', '.join(ALLOWED_SUFFIXES)}` (or no extension)\n"
    f"version is auto-detected from the file header — no engine argument needed."
)


@client.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return
    if not message.content.startswith(PREFIX):
        return

    if not _channel_ok(message):
        try:
            await message.reply(
                "this command is not allowed in this channel.",
                mention_author=False,
                delete_after=10,
            )
        except discord.HTTPException:
            pass
        return

    rest = message.content[len(PREFIX):].strip()
    first_token = rest.split(maxsplit=1)[0].lower() if rest else ""
    has_attachment = bool(message.attachments)

    # ---- explicit subcommands ----
    if first_token == "ping":
        await message.reply("alive", mention_author=False)
        return

    if first_token == "stats":
        up = time.time() - STARTED_AT
        hours, rem = divmod(int(up), 3600)
        minutes, seconds = divmod(rem, 60)
        embed = discord.Embed(title="luraph-bot stats", color=0x5865F2)
        embed.add_field(name="Queue", value=f"{_queue_depth()} pending", inline=True)
        embed.add_field(name="Uptime", value=f"{hours}h {minutes}m {seconds}s", inline=True)
        embed.add_field(
            name="Channels",
            value="any" if ALLOWED_CHANNELS is None else f"{len(ALLOWED_CHANNELS)} locked",
            inline=True,
        )
        await message.reply(embed=embed, mention_author=False)
        return

    if first_token in ("help", "h"):
        await message.reply(HELP_TEXT, mention_author=False)
        return

    # ---- figure out the source and mode ----
    detect_only = False
    mode = "smart"
    source_text = rest

    if first_token == "detect":
        detect_only = True
        source_text = rest[len("detect"):].strip()
    elif first_token == "trace":
        mode = "trace"
        source_text = rest[len("trace"):].strip()
    elif first_token == "strings":
        mode = "strings"
        source_text = rest[len("strings"):].strip()
    elif first_token == "full":
        mode = "full"
        source_text = rest[len("full"):].strip()

    if not rest and not has_attachment:
        await message.reply(HELP_TEXT, mention_author=False)
        return

    if not source_text and has_attachment:
        source_text = None

    left = _cooldown_left(message.author.id)
    if left > 0.5:
        await message.reply(
            f"you're on cooldown — try again in {int(left)}s.",
            mention_author=False,
            delete_after=8,
        )
        return

    if _queue_depth() >= MAX_QUEUE_DEPTH:
        await message.reply(
            f"queue is full ({MAX_QUEUE_DEPTH} pending). Try again shortly.",
            mention_author=False,
            delete_after=10,
        )
        return

    try:
        data, name = await _resolve_source(message, source_text)
    except SourceError as e:
        await message.reply(str(e), mention_author=False)
        return
    except Exception as e:  # noqa: BLE001
        await message.reply(f"internal error: `{e}`", mention_author=False)
        return

    if detect_only:
        info = _scan_bytes(data)
        if not info["found"]:
            await message.reply(
                "no Luraph banner found in the first 8 KB — "
                "header may be stripped or it's another obfuscator.",
                mention_author=False,
            )
            return
        embed = discord.Embed(title="Luraph header scan", color=0x5865F2)
        embed.add_field(name="Version", value=f"`v{info['version']}`", inline=True)
        embed.add_field(name="Engine", value=f"`{info['engine']}`", inline=True)
        if info.get("url"):
            embed.add_field(name="URL", value=info["url"], inline=False)
        embed.add_field(name="Banner", value=f"`{info['banner'][:1000]}`", inline=False)
        embed.add_field(name="Dispatch", value=describe_dispatch(info, None), inline=False)
        await message.reply(embed=embed, mention_author=False)
        return

    _last_run[message.author.id] = time.time()
    try:
        await _run_job(message, data, name, mode=mode)
    except Exception as e:  # noqa: BLE001
        try:
            await message.reply(f"job failed: `{e}`", mention_author=False)
        except discord.HTTPException:
            pass


# ---------------------------------------------------------------- lifecycle

_ready_logged = False


@client.event
async def on_ready():
    global _ready_logged
    if _ready_logged:
        return
    _ready_logged = True
    if ALLOWED_CHANNELS is None:
        lock = "open to ALL channels"
    else:
        lock = f"locked to {sorted(ALLOWED_CHANNELS)}"
    print(f"[bot] logged in as {client.user} ({client.user.id})", flush=True)
    print(f"[bot] prefix = {PREFIX!r}, {lock}", flush=True)
    print(f"[bot] watching {IN}, results in {OUT}", flush=True)


def main() -> None:
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise SystemExit("DISCORD_TOKEN is not set")
    token = token.strip()
    if token.startswith("Bot "):
        token = token[4:].strip()
    if token.count(".") != 2:
        raise SystemExit(
            "DISCORD_TOKEN does not look like a bot token "
            "(expected three dot-separated parts). Reset the token in the "
            "Discord Developer Portal and paste it exactly, no quotes."
        )
    client.run(token, log_handler=None)


if __name__ == "__main__":
    main()
