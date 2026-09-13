#!/usr/bin/env bash
# KARGU-OSINT installer. Recreates everything a fresh clone lacks, entirely under this folder.
# Nothing is installed system-wide; delete the folder and the tools are gone with it.
# Re-runnable: anything already present is skipped.
set -euo pipefail

OSINT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$OSINT"
PY="${OSINT_PYTHON:-/usr/bin/python3}"
[ -x "$PY" ] || PY="$(command -v python3)"

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m-> %s\033[0m\n' "$*"; }
warn() { printf '   \033[33m!  %s\033[0m\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

step "Prerequisites"
ok "python: $("$PY" --version 2>&1)"
if ! "$PY" -c 'import flask, requests, PIL, socks' 2>/dev/null; then
  warn "missing Python packages for the engine — install them with:"
  echo "        $PY -m pip install --user -r requirements.txt"
fi
for c in git curl perl tar; do have "$c" || warn "$c not found — needed for the downloads below"; done

step "pipx (private, under .bootstrap/)"
if [ ! -x .bootstrap/bin/pipx ]; then
  "$PY" -m venv .bootstrap
  .bootstrap/bin/pip install -q "pipx==1.17.1"
fi
export PIPX_HOME="$OSINT/pipx" PIPX_BIN_DIR="$OSINT/pipx/bin"
PIPX=.bootstrap/bin/pipx
ok "$($PIPX --version 2>/dev/null | head -1)"

step "OSINT tools (pipx, pinned versions)"
for spec in sherlock-project==0.16.0 maigret==0.6.5 holehe==1.61 h8mail==2.5.6 \
            socialscan==2.0.1 dnstwist==20250130 instaloader==4.15.3; do
  name="${spec%%==*}"
  if [ -d "pipx/venvs/$name" ]; then ok "$name (present)"
  else "$PIPX" install -q "$spec" && ok "$spec"; fi
done

step "theHarvester (git checkout + its own venv)"
if [ ! -d tools/theHarvester ]; then
  git clone -q https://github.com/laramies/theHarvester tools/theHarvester
  git -C tools/theHarvester checkout -q 903a35e
fi
if [ ! -x tools/theHarvester/.venv/bin/theHarvester ]; then
  ( cd tools/theHarvester && "$PY" -m venv .venv && .venv/bin/pip install -q . )
fi
ok "tools/theHarvester/.venv/bin/theHarvester"

step "ExifTool (vendored Perl)"
if [ ! -x tools/exiftool-master/exiftool ]; then
  mkdir -p tools
  curl -sL https://github.com/exiftool/exiftool/archive/refs/heads/master.tar.gz | tar xz -C tools
fi
ok "exiftool $(tools/exiftool-master/exiftool -ver 2>/dev/null || echo '(perl missing?)')"

step "PhoneInfoga (static binary, linux x86_64)"
if [ ! -x bin/phoneinfoga ]; then
  mkdir -p bin
  curl -sL https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz \
    | tar xz -C bin phoneinfoga
  chmod +x bin/phoneinfoga
fi
ok "$(bin/phoneinfoga version 2>/dev/null | head -1)"

step "bin/ links"
for pair in sherlock:sherlock-project maigret:maigret update_sitesmd:maigret holehe:holehe \
            h8mail:h8mail socialscan:socialscan dnstwist:dnstwist instaloader:instaloader; do
  cmd="${pair%%:*}"; venv="${pair##*:}"
  ln -sfn "../pipx/venvs/$venv/bin/$cmd" "bin/$cmd"
done
chmod +x bin/exiftool bin/theHarvester bin/sf kargu kargu-new kargu-ui kargu-tor kargu-dash dashboard/install-ml.sh
ok "bin/ populated"

step "Runtime directories and config"
mkdir -p cases notes .tor
if [ ! -f config/.env ]; then
  cp config/.env.example config/.env && chmod 600 config/.env
  ok "config/.env created from the template — add API keys there (optional)"
else ok "config/.env present"; fi

step "OPSEC layer — checked, not installed"
have tor          && ok "tor"          || warn "tor missing: --tor needs it            (dnf/apt install tor)"
have proxychains4 && ok "proxychains4" || warn "proxychains-ng missing: without it --tor covers this program's own requests but not sherlock/maigret"
have mullvad      && ok "mullvad"      || warn "mullvad missing: the report will show a 'direct' exit; any VPN works, Mullvad is the one the scanner can detect"
if have docker; then
  if docker image inspect smicallef/spiderfoot >/dev/null 2>&1; then ok "SpiderFoot image"
  else
    warn "SpiderFoot image missing (needed only for --deep). The Docker Hub image no longer exists; build it locally:"
    echo "        git clone https://github.com/smicallef/spiderfoot tools/spiderfoot && chmod -R a+rX tools/spiderfoot"
    echo "        docker build --network=host -t smicallef/spiderfoot tools/spiderfoot"
  fi
else warn "docker missing: --deep (SpiderFoot) unavailable"; fi

step "Shortcuts"
mkdir -p "$HOME/.local/bin"
for c in kargu kargu-new kargu-ui kargu-tor kargu-dash; do ln -sfn "$OSINT/$c" "$HOME/.local/bin/$c"; done
ok "kargu, kargu-new, kargu-ui, kargu-tor, kargu-dash -> ~/.local/bin"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) warn "~/.local/bin is not on PATH";; esac

step "Self-test"
"$PY" tests/test_verify.py 2>&1 | tail -1
for t in sherlock maigret holehe socialscan dnstwist instaloader theHarvester exiftool phoneinfoga; do
  if "bin/$t" --help >/dev/null 2>&1 || "bin/$t" -h >/dev/null 2>&1 || "bin/$t" -ver >/dev/null 2>&1 || "bin/$t" version >/dev/null 2>&1
  then ok "$t"; else warn "$t is not runnable"; fi
done
printf '\nDone. Try:  kargu-new\n'
