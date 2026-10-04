"""
Discord bot for the Luraph deobfuscator — prefix commands, auto-detect.

Usage (prefix is `.lph`):
    .lph <attachment>          run the deobfuscator on an attached file
    .lph <url>                 same, but download the file from a URL
    .lph detect <attachment>   only scan the header
    .lph detect <url>
    .lph help                  show usage
    .lph ping                  health check
    .lph stats                 queue depth and uptime

The version is auto-detected from the Luraph banner in the file header
(scanner.py), and the dispatcher picks the right front end:

    v14.7 / v14.8 / v14.9   ->  cli.py --engine 14.x
    v14.0 .. v14.6, v14     ->  cli.py --engine auto
    v15 / v15.x             ->  deob.py --obfuscator luraph_v15

Accepted extensions: .lua .luau .lph .txt
URL fetching is SSRF-guarded (only http/https, only public IPs,
manual redirect checks). No size cap.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import json
import os
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
ALLOWED_CHANNEL = os.environ.get("ALLOWED_CHANNEL_ID") or None
STARTED_AT = time.time()

ALLOWED_SUFFIXES = (".lua", ".luau", ".lph", ".txt")
FORBIDDEN_SUFFIXES = (
    ".exe", ".dll", ".so", ".dylib",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".py", ".pyc", ".bat", ".cmd", ".ps1", ".sh", ".js",
)

MAX_QUEUE_DEPTH = 32

URL_TIMEOUT = 120.0
URL_MAX_REDIRECTS = 5
ALLOWED_SCHEMES = {"http", "https"}

USER_COOLDOWN = 10.0
_last_run: dict[int, float] = {}

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
    return ALLOWED_CHANNEL is None or str(message.channel.id) == ALLOWED_CHANNEL


def _bad_ext(name: str) -> bool:
    low = name.lower()
    if low.endswith(FORBIDDEN_SUFFIXES):
        return True
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
    """
    Returns (data, error, final_url). No size cap — reads the whole body.
    """
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
    low = s.lower()
    return low.startswith("http://") or low.startswith("https://")


# ---------------------------------------------------------------- source extraction

class SourceError(Exception):
    pass


async def _resolve_source(message: discord.Message, arg: str | None) -> tuple[bytes, str]:
    """Return (data, original_name) or raise SourceError."""
    if message.attachments:
        att = message.attachments[0]
        if _bad_ext(att.filename):
            raise SourceError(
                f"refusing `{att.filename}` — allowed: {', '.join(ALLOWED_SUFFIXES)}"
            )
        try:
            data = await att.read()
        except discord.HTTPException as e:
            raise SourceError(f"failed to download the attachment: `{e}`") from e
        return data, att.filename

    if arg and _looks_like_url(arg):
        ok, err = _safe_url(arg)
        if not ok:
            raise SourceError(err)
        data, err, final_url = await _fetch_url(arg)
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

    raise SourceError(
        "attach a file or paste a direct `http(s)://` link.\n"
        f"usage: `{PREFIX} <file|url>` — try `{PREFIX} help`"
    )


# ---------------------------------------------------------------- job runner

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
            body = res["error"][:1800]
            await message.reply(
                f"deobfuscation failed:\n```\n{body}\n```",
                mention_author=False,
            )
            return

        out_path = Path(res["output"])
        payload = out_path.read_bytes()
        out_path.unlink(missing_ok=True)

        stem = Path(original_name).stem or "output"
        name = f"{stem}.deobf.luau"

        elapsed = res.get("elapsed", 0)
        extra = ""
        rinfo = res.get("scan") or {}
        if rinfo.get("found"):
            extra = f" · Luraph v{rinfo['version']}"

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
    f"`{PREFIX} <attachment>` — deobfuscate an attached file\n"
    f"`{PREFIX} <url>` — deobfuscate a file at a direct http(s) link\n"
    f"`{PREFIX} detect <attachment|url>` — scan the header only\n"
    f"`{PREFIX} help` — this message\n"
    f"`{PREFIX} ping` — health check\n"
    f"`{PREFIX} stats` — queue depth and uptime\n\n"
    f"accepted: `{', '.join(ALLOWED_SUFFIXES)}`\n"
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
                "this command is locked to another channel.",
                mention_author=False,
                delete_after=10,
            )
        except discord.HTTPException:
            pass
        return

    rest = message.content[len(PREFIX):].strip()
    parts = rest.split(maxsplit=1)
    sub = parts[0].lower() if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else None

    if sub in ("help", "", "h"):
        await message.reply(HELP_TEXT, mention_author=False)
        return

    if sub == "ping":
        await message.reply("alive", mention_author=False)
        return

    if sub == "stats":
        up = time.time() - STARTED_AT
        hours, rem = divmod(int(up), 3600)
        minutes, seconds = divmod(rem, 60)
        embed = discord.Embed(title="luraph-bot stats", color=0x5865F2)
        embed.add_field(name="Queue", value=f"{_queue_depth()} pending", inline=True)
        embed.add_field(name="Uptime", value=f"{hours}h {minutes}m {seconds}s", inline=True)
        await message.reply(embed=embed, mention_author=False)
        return

    detect_only = False
    if sub == "detect":
        detect_only = True

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
        data, name = await _resolve_source(message, arg)
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
        await _run_job(message, data, name, mode="full")
    except Exception as e:  # noqa: BLE001
        try:
            await message.reply(f"job failed: `{e}`", mention_author=False)
        except discord.HTTPException:
            pass


# ---------------------------------------------------------------- lifecycle

@client.event
async def on_ready():
    print(f"[bot] logged in as {client.user} ({client.user.id})", flush=True)
    print(f"[bot] prefix = {PREFIX!r}, watching {IN}, results in {OUT}", flush=True)


def main() -> None:
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        raise SystemExit("DISCORD_TOKEN is not set")
    client.run(token, log_handler=None)


if __name__ == "__main__":
    main()
