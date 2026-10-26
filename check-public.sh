#!/data/data/com.termux/files/usr/bin/bash
# Fail when tracked files carry values that must stay on this device.
# Run by hand or through hooks/pre-push (git config core.hooksPath hooks).
set -uo pipefail
cd "$(dirname "$0")" || exit 1
bad=0

scan() {
  hits=$(git grep -InE "$1" -- . ':(exclude)check-public.sh' ':(exclude)hooks/pre-push' 2>/dev/null \
         | grep -vE '127\.0\.0\.1|localhost|0\.0\.0\.0' || true)
  if [ -n "$hits" ]; then
    printf 'LEAK  %s\n' "$2"
    printf '%s\n' "$hits" | head -5
    bad=1
  fi
}

scan '([0-9]{1,3}\.){3}[0-9]{1,3}'                     'public IPv4 address'
scan 'BEGIN [A-Z ]*PRIVATE KEY|ssh-(rsa|ed25519) AAAA'  'private key or public key body'
scan 'gh[pousr]_[A-Za-z0-9]{20,}'                     'GitHub token'
scan '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(com|cn|net)' 'mail address'
# /srv/build is a documented convention used in examples and smoke tests, not a personal
# value; /root and /home would point at a concrete account, so they are scanned.
scan '(/root|/home)/[A-Za-z0-9._-]+'                  'absolute host path'

if [ "$bad" -eq 0 ]; then echo 'public check: clean'; fi
exit "$bad"
