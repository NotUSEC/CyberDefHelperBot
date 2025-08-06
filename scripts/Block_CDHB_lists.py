import subprocess
import requests
import ipaddress
from pathlib import Path

# Скрипт подгружает списки по указанным ссылкам, и заносит адреса в отдельный список в iptables. Работает через списки ipset, чтобы не плодить миллиард правил в iptables.
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/NotUSEC/CyberDefHelperBot/refs/heads/main/IPlists/honeypot.txt",
    "https://raw.githubusercontent.com/NotUSEC/CyberDefHelperBot/refs/heads/main/IPlists/mainlist.txt",
]

IPSET_NAME = "blocklist_set"
IPTABLES_CHAIN = "BLOCKLIST_CHAIN"


def check_ipset():
  print("Проверяю наличие ipset...")
  ipset_path = Path("/usr/sbin/ipset")
  if ipset_path.exists():
    print("ipset установлен")
  else:
    print("[!] ipset не установлен. Установите при помощи команды: apt install ipset -y")
    exit(1)

def fetch_blocklists():
    raw_ips = set()
    for url in BLOCKLIST_URLS:
        try:
            print(f"Загружается: {url}")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                token = line.split()[0]
                try:
                    net = ipaddress.ip_network(token, strict=False)
                    raw_ips.add(str(net))
                except ValueError:
                    continue
        except Exception as e:
            print(f"[!] Ошибка загрузки {url}: {e}")
    return sorted(raw_ips)


def setup_ipset():
    subprocess.run(["ipset", "create", IPSET_NAME, "hash:net"], stderr=subprocess.DEVNULL)


def flush_ipset():
    subprocess.run(["ipset", "flush", IPSET_NAME], check=True)

def add_ips_to_ipset(ip_list):
    for ip in ip_list:
        subprocess.run(["ipset", "add", IPSET_NAME, ip], stderr=subprocess.DEVNULL)


def setup_iptables_rule():
    # Создание отдельной цепи, если её нет
    subprocess.run(["iptables", "-N", IPTABLES_CHAIN], stderr=subprocess.DEVNULL)
    subprocess.run(["iptables", "-F", IPTABLES_CHAIN], check=True)

    # Добавление правила в цепь
    subprocess.run(["iptables", "-A", IPTABLES_CHAIN, "-m", "set", "--match-set", IPSET_NAME, "src", "-j", "DROP"], check=True)

    # Подключение цепи к INPUT, если ещё не подключена
    result = subprocess.run(["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN], stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        subprocess.run(["iptables", "-I", "INPUT", "-j", IPTABLES_CHAIN], check=True)


def main():
    check_ipset()
    print("Обновление адресов для блокировки")
    ip_list = fetch_blocklists()
    setup_ipset()
    flush_ipset()
    add_ips_to_ipset(ip_list)
    setup_iptables_rule()
    print(f"Успешно обновлено. В списке сейчас {len(ip_list)} адресов/подсетей")


if __name__ == '__main__':
    main()
