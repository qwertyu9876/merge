import requests
from datetime import datetime

URLS = [
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/tuic.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt",
]

OUTPUT_FILE = "merged_proxies.txt"

def fetch_content(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Ошибка при скачивании {url}: {e}")
        return []

def main():
    all_lines = []

    for url in URLS:
        print(f"Скачивание: {url}")
        lines = fetch_content(url)
        all_lines.extend(lines)

    # Удаляем пустые строки и дубликаты
    unique_lines = sorted(set(line.strip() for line in all_lines if line.strip()))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_lines))

    print(f"Готово. Записано {len(unique_lines)} строк.")
    print(f"Время обновления: {datetime.utcnow()} UTC")

if __name__ == "__main__":
    main()
