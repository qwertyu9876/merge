import requests
import base64
import json
import socket
import uuid
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from python_v2ray.downloader import BinaryDownloader
from python_v2ray.tester import ConnectionTester
from python_v2ray.config_parser import parse_uri
import tempfile
import subprocess

# ---------------- НАСТРОЙКИ ----------------

URLS = [
    "https://github.com/seknei3/psychic-fiestas/raw/refs/heads/main/vpn_renamed.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs_tested.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
]

TARGET_FLAGS = ["🇵🇦", "🇨🇭", "🇻🇬", "🇮🇸"]

ALLOWED_SS_CIPHERS = [
    'aes-128-gcm',
    'aes-192-gcm',
    'aes-256-gcm',
    'chacha20-ietf-poly1305',
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
]

ALLOWED_VM_CIPHERS = [
    "auto",
    "aes-128-gcm",
    "chacha20-poly1305",
]

ALLOWED_ALPN = ["h2", "http/1.1"]
WEAK_PORTS = {"21", "23", "25", "110"}
TEST_URL = "https://www.google.com/generate_204"
OUTPUT_FILE = "merged_proxies.txt"

# ---------------- УТИЛИТЫ ----------------

TEST_URL = "https://www.google.com"
XRAY_PATH = "/usr/local/bin/xray"   # путь к xray

def validate_with_v2ray(proxy_uri):
    try:

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True}
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {},
                "streamSettings": {}
            }]
        }

        # python-v2ray умеет конвертировать URI
        v2 = V2Ray(
            exec_path=XRAY_PATH,
            config=config,
            uri=proxy_uri
        )

        v2.start()

        proxies = {
            "http": "socks5://127.0.0.1:10808",
            "https": "socks5://127.0.0.1:10808",
        }

        try:
            r = requests.get(TEST_URL, proxies=proxies, timeout=8)
            ok = r.status_code == 200
        except:
            ok = False

        v2.stop()

        return ok

    except:
        return False


def is_valid_uuid(val):
    try:
        uuid.UUID(val)
        return True
    except:
        return False

def is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private
    except:
        return False
        
def udp_port_open(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        sock.sendto(b"ping", (host, int(port)))

        try:
            sock.recvfrom(1024)
        except socket.timeout:
            pass

        sock.close()
        return True
    except:
        return False
        
def validate_udp_proxy(line):
    try:
        parsed = urlparse(line)

        host = parsed.hostname
        port = str(parsed.port) if parsed.port else None

        if not host or not port:
            return False

        if port in WEAK_PORTS:
            return False

        if is_private_ip(host):
            return False

        return udp_port_open(host, port)

    except:
        return False
        
def is_valid_domain(host):
    return host and "." in host and not host.replace(".", "").isdigit()

def port_open(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            return True
    except:
        return False

def fetch_content(url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return []

# ---------------- ПРОВЕРКИ ----------------

def contains_target_flag(line):
    if line.startswith("vmess://"):
        try:
            encoded = line.replace("vmess://", "")
            if len(encoded) > 5000:
                return False
            padded = encoded + "=" * (-len(encoded) % 4)
            decoded = base64.b64decode(padded).decode()
            data = json.loads(decoded)
            return any(flag in str(data.get("ps", "")) for flag in TARGET_FLAGS)
        except:
            return False

    return any(flag in unquote(line) for flag in TARGET_FLAGS)

def validate_simple_proxy(line):
    try:
        parsed = urlparse(line)

        host = parsed.hostname
        port = str(parsed.port) if parsed.port else None

        if not host or not port:
            return False

        if port in WEAK_PORTS:
            return False

        if is_private_ip(host):
            return False

        return port_open(host, port)

    except:
        return False


# ---------- VLESS ----------

def validate_vless(line):
    parsed = urlparse(line)
    params = parse_qs(parsed.query)

    host = parsed.hostname
    port = str(parsed.port) if parsed.port else None
    user = parsed.username

    if not host or not port:
        return False

    if port in WEAK_PORTS:
        return False

    if is_private_ip(host):
        return False

    if not is_valid_uuid(user):
        return False

    if params.get("allowInsecure", ["0"])[0] == "1":
        return False

    security = params.get("security", [""])[0].lower()
    #if security not in ["tls", "reality"]:
    if security not in ["reality"]:
        return False
    
    if security == "reality":
        if not params.get("pbk") or not params.get("sni"):
            return False

    alpn = params.get("alpn", [""])[0]
    if alpn and alpn not in ALLOWED_ALPN:
        return False


    if not port_open(host, port):
        return False

    return validate_with_v2ray(line)

# ---------- VMESS ----------

def validate_vmess(line):
    try:
        encoded = line.replace("vmess://", "")
        if len(encoded) > 5000:
            return False

        padded = encoded + "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(padded).decode()
        data = json.loads(decoded)

        host = data.get("add")
        port = str(data.get("port"))
        uuid_val = data.get("id")
        cipher = data.get("scy", "auto").lower()
        tls_val = str(data.get("tls", "")).lower()
        security = str(data.get("security", "")).lower()

        if not host or not port:
            return False

        if port in WEAK_PORTS:
            return False

        if is_private_ip(host):
            return False

        if not is_valid_uuid(uuid_val):
            return False

        if cipher not in ALLOWED_VM_CIPHERS:
            return False

        if tls_val not in ["reality"] and security not in ["reality"]:
            return False

        if not port_open(host, port):
            return False
    
        return validate_with_v2ray(line)

    except:
        return False

# ---------- TROJAN ----------

def validate_trojan(line):
    parsed = urlparse(line)
    params = parse_qs(parsed.query)

    host = parsed.hostname
    port = str(parsed.port) if parsed.port else None

    if not host or not port:
        return False

    if port in WEAK_PORTS:
        return False

    if is_private_ip(host):
        return False

    if params.get("allowInsecure", ["0"])[0] == "1":
        return False

    security = params.get("security", ["tls"])[0].lower()
    if security not in ["reality"]:
        return False

    if not port_open(host, port):
        return False
    
    return validate_with_v2ray(line)

# ---------- SHADOWSOCKS ----------

def validate_ss(line):
    try:
        content = line.replace("ss://", "").split("#")[0]

        if "@" not in content:
            padded = content + "=" * (-len(content) % 4)
            decoded = base64.b64decode(padded).decode()
        else:
            decoded = content

        if "@" not in decoded:
            return False

        userinfo, server = decoded.split("@", 1)
        method = userinfo.split(":")[0].lower()
        host, port = server.split(":")

        if method not in ALLOWED_SS_CIPHERS:
            return False

        if port in WEAK_PORTS:
            return False

        if is_private_ip(host):
            return False

        return port_open(host, port)

    except:
        return False

# ---------------- ОСНОВНОЙ ФИЛЬТР ----------------

def filter_line(line):
    line = line.strip()
    if not line:
        return False

    if not contains_target_flag(line):
        return False

    if line.startswith(("hysteria2://", "hy2://", "tuic://", "juicity://")):
        return validate_udp_proxy(line)
    
    if line.startswith("vless://"):
        return validate_vless(line)

    if line.startswith("vmess://"):
        return validate_vmess(line)

    if line.startswith("trojan://"):
        return validate_trojan(line)

    #if line.startswith("ss://"):
        #return validate_ss(line)

    return False

# ---------------- MAIN ----------------

def extract_host_port(line):
    try:
        parsed = urlparse(line)
        return f"{parsed.hostname}:{parsed.port}"
    except:
        return None

def main():
    all_lines = []

    for url in URLS:
        print(f"Скачивание: {url}")
        all_lines.extend(fetch_content(url))

    print("Фильтрация...")
    filtered = [line for line in all_lines if filter_line(line)]

    unique = {}
    for line in filtered:
        key = extract_host_port(line)
        if key and key not in unique:
            unique[key] = line

    result = sorted(unique.values())

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(result))

    print(f"Готово. Уникальных серверов: {len(result)}")
    print(f"Время обновления: {datetime.utcnow()} UTC")

if __name__ == "__main__":
    main()
