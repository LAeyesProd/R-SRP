#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <final-binary> <evidence-directory>" >&2
  exit 64
fi
binary="$1"
evidence="$2"
test -s "$binary"
mkdir -p "$evidence"
LC_ALL=C readelf -hW "$binary" > "$evidence/elf-header.txt"
LC_ALL=C readelf -lW "$binary" > "$evidence/elf-segments.txt"
LC_ALL=C readelf -dW "$binary" > "$evidence/elf-dynamic.txt"
LC_ALL=C readelf -SW "$binary" > "$evidence/elf-sections.txt"

grep -Eq 'Type: +DYN \(Position-Independent Executable file\)' "$evidence/elf-header.txt"
grep -Eq '\(FLAGS_1\).*PIE' "$evidence/elf-dynamic.txt"
grep -q 'GNU_RELRO' "$evidence/elf-segments.txt"
grep -Eq '\(BIND_NOW\)|\(FLAGS\).*BIND_NOW|\(FLAGS_1\).*NOW' "$evidence/elf-dynamic.txt"
# A stack segment alone does not prove NX: require RW, and reject executable stacks.
awk '
  $1 == "GNU_STACK" { count++; if ($7 != "RW" || NF != 8) bad = 1 }
  END { exit !(count == 1 && !bad) }
' "$evidence/elf-segments.txt"
if grep -Eq '\.(symtab|debug_[[:alnum:]_]+)([[:space:]]|$)' "$evidence/elf-sections.txt"; then
  echo "unstripped symbols or debug sections in release binary" >&2
  exit 1
fi
# Record dependencies without executing an untrusted binary through ldd.
grep '(NEEDED)' "$evidence/elf-dynamic.txt" > "$evidence/elf-needed.txt"
sha256sum "$binary" > "$evidence/binary.sha256"
echo "PIE, full RELRO, NX and stripping verified."
