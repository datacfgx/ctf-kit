#!/usr/bin/env bash
# Bootstrap de ferramentas de recon sem root (nmap, whatweb, gobuster, dirb).
# nikto NAO entra: pacote Kali-only, inexistente no Debian bookworm.
# /mnt tem limite de 100MiB POR ARQUIVO -> tar vazado em partes de 90m.
# Uso:
#   bash REPLICAR_kali_tools.sh          # baixa, extrai em /tmp/kaliroot, grava partes em /mnt
#   bash REPLICAR_kali_tools.sh untar    # restaura /tmp/kaliroot das partes (segundos, por turno)
set -u
KROOT=/tmp/kaliroot
STATE=/tmp/aptstate
TAR=/mnt/agents/output/kaliroot.tar.gz

if [ "${1:-}" = "untar" ]; then
  ls "$TAR"-part-* >/dev/null 2>&1 || { echo "partes ausentes: $TAR-part-*"; exit 1; }
  rm -rf "$KROOT"; mkdir -p "$KROOT"
  cat "$TAR"-part-* | tar xz -C /tmp
  echo "ok: $KROOT"; exit 0
fi

mkdir -p "$KROOT" "$STATE/lists/partial" /tmp/debs
apt-get -o Dir::State="$STATE" -o Dir::Cache="$STATE/cache" update >/dev/null 2>&1 || true

python3 - "$STATE" > /tmp/pkglist.txt <<'PY'
import subprocess, re, sys
state = sys.argv[1]
seeds = ["nmap", "whatweb", "gobuster", "dirb"]
seen, out = set(), []
for s in seeds:
    r = subprocess.run(["apt-cache", "-o", "Dir::State=" + state, "depends", "--recurse",
                        "--no-recommends", "--no-suggests", "--no-conflicts",
                        "--no-breaks", "--no-replaces", "--no-enhances", s],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        m = re.match(r"\s+(?:PreDepends|Depends):\s+(\S+)", line)
        cand = m.group(1) if m else (line.strip() if (line and line[0] not in " |") else None)
        if cand and not cand.startswith("<") and cand not in seen:
            seen.add(cand); out.append(cand)
print("\n".join(out))
PY

cd /tmp/debs
while read -r p; do
  [ -n "$p" ] || continue
  apt-get -o Dir::State="$STATE" download "$p" >/dev/null 2>&1 || echo "falhou: $p"
done < /tmp/pkglist.txt
rm -rf "$KROOT"; mkdir -p "$KROOT"
for d in /tmp/debs/*.deb; do
  [ -e "$d" ] && dpkg-deb -x "$d" "$KROOT" 2>/dev/null
done
rm -f "$TAR"-part-*
(cd /tmp && tar czf - kaliroot | split -b 90m - "$TAR"-part-)
echo "pronto: $(ls "$TAR"-part-* | wc -l) partes"
