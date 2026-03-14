import asyncio
import base64
import json
import aiohttp
from urllib.parse import urlparse, parse_qs

SUB_URLS = [
"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
"https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
"https://github.com/4n0nymou3/multi-proxy-config-fetcher/raw/refs/heads/main/configs/proxy_configs.txt",
"https://github.com/freefq/free/raw/refs/heads/master/v2",
"https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
"https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/full/5ubscrpt10n.txt",
"https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
"https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
"https://raw.githubusercontent.com/mehran1404/Sub_Link/refs/heads/main/V2RAY-Sub.txt",
"https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
"https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
"https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs.txt",
"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
"https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt",
"https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
"https://github.com/nyeinkokoaung404/V2ray-Configs/raw/refs/heads/main/All_Configs_Sub.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/1.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/2.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/3.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/4.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/5.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/6.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/7.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/8.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/9.txt",
"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/10.txt",
"https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/All_proxies.txt",
"https://raw.githubusercontent.com/Surfboardv2ray/v2ray-worker-sub/refs/heads/master/providers/providers",
"https://raw.githubusercontent.com/Surfboardv2ray/v2ray-worker-sub/refs/heads/master/providers/ir",
"https://raw.githubusercontent.com/Surfboardv2ray/v2ray-worker-sub/refs/heads/master/providers/configshubIR",
"https://raw.githubusercontent.com/trio666/proxy-checker/refs/heads/main/all.txt",
"https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",
"https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/submerge/converted.txt",
"https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/all.txt",
"https://raw.githubusercontent.com/lagzian/SS-Collector/refs/heads/main/mix.txt",
"https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
"https://raw.githubusercontent.com/ssrsub/ssr/refs/heads/master/hysteria2.txt",
"https://raw.githubusercontent.com/ssrsub/ssr/refs/heads/master/hysteria.txt",
"https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/refs/heads/main/subscribe/v2ray.txt",
"https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
"https://raw.githubusercontent.com/aiboboxx/v2rayfree/refs/heads/main/v2",
"https://raw.githubusercontent.com/Edudotnexx/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
"https://raw.githubusercontent.com/Firmfox/proxify/main/v2ray_configs/seperated_by_protocol/other.txt",
"https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
"https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/all.txt",
"https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/refs/heads/main/proxies/all.txt",
"https://msnake.serv00.net/666.txt",
"https://msnake.serv00.net/sub10.txt",
"https://msnake.serv00.net/sub9.txt",
"https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/all-proxies.txt",
"https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/refs/heads/master/list_raw.txt",
"https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
"https://raw.githubusercontent.com/prxchk/proxy-list/refs/heads/main/all.txt",
]


def try_decode_base64(data: str):
    try:
        decoded = base64.b64decode(data).decode()
        if "://" in decoded:
            return decoded
    except:
        pass
    return data


def extract_host_port(link: str):
    try:
        if link.startswith("vmess://"):
            payload = link.replace("vmess://", "")
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(payload).decode())
            return data.get("add"), int(data.get("port"))

        parsed = urlparse(link)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port

    except:
        pass

    return None, None


def is_xhttp_reality(link):
    if not link.startswith(("vless://", "trojan://")):
        return False

    try:
        params = parse_qs(urlparse(link).query)
        return (
            params.get("type", [""])[0] == "xhttp"
            and params.get("security", [""])[0] == "reality"
        )
    except:
        return False


def is_shadowtls(link):
    if not link.startswith("vless://"):
        return False

    try:
        params = parse_qs(urlparse(link).query)

        if "shadowtls" in params:
            return True

        plugin = params.get("plugin", [""])[0].lower()
        security = params.get("security", [""])[0].lower()

        return "shadow" in plugin or security == "shadowtls"

    except:
        return False


def is_hysteria2(link):
    return link.startswith("hy2://") or link.startswith("hysteria2://")


def is_tuic(link):
    return link.startswith("tuic://")


def is_naive(link):
    return link.startswith("naive+https://")


async def fetch_subscription(session, url):
    try:
        async with session.get(url, timeout=20) as r:
            text = await r.text()
            text = try_decode_base64(text)
            return text.strip().splitlines()
    except:
        return []


async def tcp_ping(host, port, timeout=3):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout)

        writer.close()
        await writer.wait_closed()

        return True
    except:
        return False


async def check_proxy(proxy):
    host, port = extract_host_port(proxy)

    if not host:
        return None

    alive = await tcp_ping(host, port)

    if alive:
        return proxy

    return None


async def main():

    unique = set()
    filtered = []

    timeout = aiohttp.ClientTimeout(total=20)

    async with aiohttp.ClientSession(timeout=timeout) as session:

        tasks = [fetch_subscription(session, url) for url in SUB_URLS]
        results = await asyncio.gather(*tasks)

        for links in results:

            for link in links:

                link = link.strip()

                if not (
                    is_xhttp_reality(link)
                    or is_shadowtls(link)
                    or is_hysteria2(link)
                    or is_tuic(link)
                    or is_naive(link)
                ):
                    continue

                host, port = extract_host_port(link)

                if host:
                    server = f"{host}:{port}"

                    if server not in unique:
                        unique.add(server)
                        filtered.append(link)

    print(f"Filtered proxies: {len(filtered)}")

    tasks = [check_proxy(p) for p in filtered]

    alive = []

    for future in asyncio.as_completed(tasks):

        result = await future

        if result:
            alive.append(result)

    print(f"Alive proxies: {len(alive)}")

    with open("merged_proxies.txt", "w", encoding="utf-8") as f:
        for proxy in alive:
            f.write(proxy + "\n")


if __name__ == "__main__":
    asyncio.run(main())
