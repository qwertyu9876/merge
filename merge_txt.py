import requests
import base64
import json
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime

URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/tuic.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/seknei3/psychic-fiestas/refs/heads/main/vpn.txt",
]

OUTPUT_FILE = "merged_proxies.txt"

# Флаги стран
TARGET_FLAGS = ["🇵🇦", "🇸🇬", "🇨🇭", "🇻🇬", "🇮🇸"]


def fetch_content(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Ошибка при скачивании {url}: {e}")
        return []


def contains_target_flag(line):
    # ---- VMESS ----
    if line.startswith("vmess://"):
        try:
            encoded = line.replace("vmess://", "")
            padded = encoded + "=" * (-len(encoded) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            data = json.loads(decoded)

            ps = str(data.get("ps", ""))
            return any(flag in ps for flag in TARGET_FLAGS)
        except Exception:
            return False

    # ---- Остальные ----
    decoded_line = unquote(line)
    return any(flag in decoded_line for flag in TARGET_FLAGS)


def has_reality_vless(line):
    parsed = urlparse(line)
    params = parse_qs(parsed.query)
    security = params.get("security", [""])[0].lower()
    return security in ["reality"]


def has_tls_or_reality_trojan(line):
    parsed = urlparse(line)
    params = parse_qs(parsed.query)
    security = params.get("security", [""])[0].lower()
    return security in ["tls", "reality"]


def has_tls_or_reality_vmess(line):
    try:
        encoded = line.replace("vmess://", "")
        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(padded).decode("utf-8")
        data = json.loads(decoded)

        tls_value = str(data.get("tls", "")).lower()
        security_value = str(data.get("security", "")).lower()

        return tls_value in ["tls", "reality"] or security_value in ["tls", "reality"]
    except Exception:
        return False


def extract_host_port(line):
    try:
        # -------- VMESS --------
        if line.startswith("vmess://"):
            encoded = line.replace("vmess://", "")
            padded = encoded + "=" * (-len(encoded) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            data = json.loads(decoded)

            host = data.get("add")
            port = str(data.get("port"))

            if host and port:
                return f"{host}:{port}"
            return None

        # -------- SHADOWSOCKS --------
        if line.startswith("ss://"):
            content = line.replace("ss://", "").split("#")[0]

            # если есть @ — значит часть уже декодирована
            if "@" in content:
                userinfo, server = content.split("@", 1)
            else:
                # нужно декодировать base64
                padded = content + "=" * (-len(content) % 4)
                decoded = base64.b64decode(padded).decode("utf-8")
                if "@" not in decoded:
                    return None
                userinfo, server = decoded.split("@", 1)

            host, port = server.split(":")
            return f"{host}:{port}"

        # -------- ОСТАЛЬНЫЕ ПРОТОКОЛЫ --------
        parsed = urlparse(line)
        host = parsed.hostname
        port = parsed.port

        if host and port:
            return f"{host}:{port}"

    except Exception:
        pass

    return None


def filter_line(line):
    line = line.strip()
    if not line:
        return False

    # Проверка флага страны
    if not contains_target_flag(line):
        return False

    if line.startswith("vless://"):
        return has_reality_vless(line)

    if line.startswith("vmess://"):
        return has_tls_or_reality_vmess(line)

    if line.startswith("trojan://"):
        return has_tls_or_reality_trojan(line)

    # Остальные протоколы (например ss://, hy2://, tuic://)
    return True


def main():
    all_lines = []

    for url in URLS:
        print(f"Скачивание: {url}")
        lines = fetch_content(url)
        all_lines.extend(lines)

    filtered = [line for line in all_lines if filter_line(line)]

    # --- ДЕДУПЛИКАЦИЯ ПО HOST:PORT ---
    unique_servers = {}
    for line in filtered:
        key = extract_host_port(line)
        if key and key not in unique_servers:
            unique_servers[key] = line

    def protocol_priority(line):
        if line.startswith("vless://"):
            return (0, line)
        if line.startswith("trojan://"):
            return (1, line)
        if line.startswith("vmess://"):
            return (2, line)
        if line.startswith("ss://"):
            return (3, line)
        return (4, line)  # остальные протоколы
    
    unique_lines = sorted(unique_servers.values(), key=protocol_priority)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_lines))

    print(f"Готово. Записано {len(unique_lines)} уникальных серверов.")
    print(f"Время обновления: {datetime.utcnow()} UTC")


if __name__ == "__main__":
    main()
