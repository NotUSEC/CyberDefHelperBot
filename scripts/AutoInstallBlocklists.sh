#!/bin/bash

set -euo pipefail

#### Переменные
# Списки с IP-адресами
BLOCKLIST_URLS=(
  "https://raw.githubusercontent.com/NotUSEC/CyberDefHelperBot/refs/heads/main/IPlists/honeypot.txt"
  "https://raw.githubusercontent.com/NotUSEC/CyberDefHelperBot/refs/heads/main/IPlists/mainlist.txt"
  "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
)
# Пути до временных файлов
UPDATE_SCRIPT="/usr/local/bin/update_blacklist.sh"
TMP_LIST="/tmp/ip-blocklist.txt"
NFT_SET_FILE="/tmp/nft-blocklist.nft"

if ! command -v /usr/sbin/nft &>/dev/null; then
    echo "[+] Устанавливается nftables..."
    apt-get update && apt-get install -y nftables
fi

if ! command -v nft &>/dev/null && [ -x /usr/sbin/nft ]; then
    export PATH="/usr/sbin:$PATH"
fi

if ! command -v nft &>/dev/null; then
    echo "[!] Команда 'nft' не найдена."
    exit 1
fi

echo "[+] Первичная настройка nftables..."
nft list table inet blacklist &>/dev/null || nft -f - <<EOF_RULES
add table inet blacklist
add set inet blacklist blocked_ips { type ipv4_addr; flags interval; }
add chain inet blacklist filter_in {
    type filter hook input priority 0; policy accept;
    ip saddr @blocked_ips drop
}
add chain inet blacklist filter_out {
    type filter hook output priority 0; policy accept;
    ip daddr @blocked_ips drop
}
EOF_RULES

cat <<EOF > "$UPDATE_SCRIPT"
#!/bin/bash
set -euo pipefail
export PATH="/usr/sbin:/sbin:\$PATH"

BLOCKLIST_URLS=(
EOF
for url in "${BLOCKLIST_URLS[@]}"; do
  echo "  \"$url\"" >> "$UPDATE_SCRIPT"
done
cat <<'EOF_UPDATE' >> "$UPDATE_SCRIPT"
)
TMP_LIST="/tmp/ip-blocklist.txt"
NFT_SET_FILE="/tmp/nft-blocklist.nft"

> "$TMP_LIST"

for url in "${BLOCKLIST_URLS[@]}"; do
  echo "[*] Загружается: $url"
  curl -fsSL "$url" >> "$TMP_LIST" || true
  echo >> "$TMP_LIST"
done

BLOCKED_IPS=$(python3 - <<EOF
import ipaddress
with open("$TMP_LIST") as f:
    nets = []
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        token = line.split()[0]
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    for net in ipaddress.collapse_addresses(nets):
        print(net)
EOF
)

{
  echo "flush set inet blacklist blocked_ips"
  echo -n "add element inet blacklist blocked_ips {"
  first=1
  while IFS= read -r ip; do
    if [[ -n "$ip" ]]; then
      if [[ $first -eq 1 ]]; then
        echo -n " $ip"
        first=0
      else
        echo -n ", $ip"
      fi
    fi
  done <<< "$BLOCKED_IPS"
  echo " }"
} > "$NFT_SET_FILE"

nft -f "$NFT_SET_FILE"
EOF_UPDATE

chmod +x "$UPDATE_SCRIPT"
echo "[+] Скрипт обновления создан: $UPDATE_SCRIPT"

# Добавление в cron
if ! crontab -l 2>/dev/null | grep -q "$UPDATE_SCRIPT"; then
  echo "[+] Добавление в cron (ежечасно)"
  (crontab -l 2>/dev/null; echo "0 * * * * $UPDATE_SCRIPT >/dev/null 2>&1") | crontab -
fi

$UPDATE_SCRIPT

echo "[+] Установка и первая загрузка завершены."
