# syntax=docker/dockerfile:1.7

# ============================================================
# stage 1 — build Luau from source
# ============================================================
FROM debian:bookworm-slim AS luau-build

RUN apt-get update && apt-get install -y --no-install-recommends \
      git cmake g++ make ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch 0.739 https://github.com/luau-lang/luau.git

# same source patch build_luau.py applies: leave the vector metatable writable
# so envlog.luau can install Roblox's Vector3 members (Magnitude, Dot, ...)
RUN python3 - <<'EOF'
import pathlib, sys
p = pathlib.Path("luau/VM/src/lveclib.cpp")
t = p.read_text()
old = "    lua_setreadonly(L, -1, true);\n    lua_pop(L, 1); // pop the metatable\n"
new = "    // deobf: left writable, envlog.luau adds Roblox's Vector3 members\n    lua_pop(L, 1); // pop the metatable\n"
if new not in t:
    if old not in t:
        sys.exit("lveclib.cpp changed upstream: patch by hand")
    p.write_text(t.replace(old, new))
EOF

RUN cmake -S luau -B build -DCMAKE_BUILD_TYPE=Release -DLUAU_BUILD_TESTS=OFF \
 && cmake --build build --parallel

RUN set -eux; \
    luau_bin=$(find build -maxdepth 3 -type f -name luau -executable | head -n1); \
    ast_bin=$(find build -maxdepth 3 -type f -name luau-ast -executable | head -n1); \
    [ -n "$luau_bin" ] || { echo "luau binary not found"; ls -R build; exit 1; }; \
    [ -n "$ast_bin" ]  || { echo "luau-ast binary not found"; ls -R build; exit 1; }; \
    mkdir -p /out; \
    cp "$luau_bin" /out/luau; \
    cp "$ast_bin"  /out/luau-ast; \
    chmod +x /out/luau /out/luau-ast

# ============================================================
# stage 2 — bot + worker runtime
# ============================================================
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 -s /usr/sbin/nologin app

WORKDIR /app

COPY bot/requirements.txt /app/bot/requirements.txt
RUN pip install --no-cache-dir -r /app/bot/requirements.txt

# linux luau binaries replace the windows ones from the repo
COPY --from=luau-build /out/luau     /app/deobf/bin/luau
COPY --from=luau-build /out/luau-ast /app/deobf/bin/luau-ast
RUN chmod +x /app/deobf/bin/luau /app/deobf/bin/luau-ast

COPY Deobfuscator/deobf/ /app/deobf/
COPY bot/ /app/bot/

RUN mkdir -p /jobs/in /jobs/out && chown -R app:app /jobs /app

USER app
WORKDIR /app/bot

CMD ["python", "app.py"]
