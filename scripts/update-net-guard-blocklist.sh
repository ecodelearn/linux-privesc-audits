#!/usr/bin/env bash
# Gera um blocklist.conf pro net_guard a partir da lista Spamhaus DROP,
# preservando entradas manuais e respeitando um teto de capacidade --
# ver audits/2026-07-17-firewall-opensnitch-netguard/ pro porquê do teto
# (o mapa BPF do net_guard falha com "No space left on device" e ENTRA
# EM CRASH LOOP, em vez de só ignorar o excesso, acima de ~1024 entradas).
#
# Uso: update-net-guard-blocklist.sh [max_entries_spamhaus] > blocklist.conf
# Depois: sudo cp blocklist.conf /etc/net_guard/blocklist.conf && sudo systemctl restart net_guard

set -euo pipefail

MAX_SPAMHAUS="${1:-999}"
MANUAL_ENTRIES=(
    "1.1.1.1"
)

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

curl -sL --max-time 15 https://www.spamhaus.org/drop/drop.txt -o "$tmp"

echo "# net_guard blocklist"
echo "# Uma regra por linha: IPv4 ou IPv4/prefixlen. Linhas em branco e '#' sao ignoradas."
echo "#"
echo "# --- entradas manuais ---"
for e in "${MANUAL_ENTRIES[@]}"; do
    echo "$e"
done
echo
echo "# --- Spamhaus DROP list (netblocks sequestrados/usados por crime organizado) ---"
echo "# Fonte: https://www.spamhaus.org/drop/drop.txt"
echo "# Baixado em: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# LIMITADO a $MAX_SPAMHAUS entradas -- ver aviso no topo do arquivo sobre capacidade do mapa BPF"
grep -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?' "$tmp" | head -n "$MAX_SPAMHAUS"
