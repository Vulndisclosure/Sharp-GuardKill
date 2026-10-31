#!/bin/bash
set -e

TERM=dumb mcs -target:exe -platform:x64 -optimize+ \
  -out:CredGuardKill.exe \
  -r:System.dll \
  CredGuardKill.cs

echo "[+] Build done! : CredGuardKill.exe"
