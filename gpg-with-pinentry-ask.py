#!/usr/bin/env python3

import subprocess
import sys

args = sys.argv[1:]

i = 0
while i < len(args):
    if args[i] == '--pinentry-mode':
        del args[i]  # --pinentry-mode
        del args[i]  # loopback
    if args[i] == '--passphrase-fd':
        del args[i]  # --passphrase-fd
        del args[i]  # 0
    i += 1

proc = subprocess.run(
    ['gpg', '--pinentry-mode', 'ask', *args],
    stdin=sys.stdin,
    stdout=sys.stdout,
    stderr=sys.stderr,
)
