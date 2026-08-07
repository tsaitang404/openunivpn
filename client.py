#!/usr/bin/env python3
"""
UniVPN 开源客户端 — 自动选最优网关 + TUN 模式

用法:
  1. python3 auth.py                     # Web 认证
  2. sudo python3 client.py              # 启动 VPN (自动选最快网关)
  3. dae 分流内网段到 cnem0 / 浏览器直接访问内网 IP
"""
import socket, ssl, struct, json, sys, os, time, threading, select, fcntl, subprocess, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import load_config, setup_wizard, SESSION_FILE, DATA_DIR

CNEM_MAGIC = 0xBEEFFCFE
CNEM_SESSION = 0xD6A492C1
CMD_ACL = 0x0006
CMD_REQVIP = 0x0003
CMD_DATA = 0x0002
CMD_KEEPALIVE = 0x0005

be32 = lambda v: struct.pack(">I", v & 0xFFFFFFFF)
be16 = lambda v: struct.pack(">H", v & 0xFFFF)
MAGIC_B = struct.pack("<I", CNEM_MAGIC)
SESS_B = struct.pack("<I", CNEM_SESSION)

KEEPALIVE_FRAME = MAGIC_B + SESS_B + be32(0) + be16(CMD_KEEPALIVE) + be16(0)

def cnem_frame(cmd, payload=b"", ctx1f4=0, extra_be32=None):
    if extra_be32 is not None:
        payload = payload + be32(extra_be32)
    return MAGIC_B + SESS_B + be32(ctx1f4) + be16(cmd) + be16(len(payload)) + payload

def parse_cnem(data):
    if len(data) < 16:
        return None, None, data
    cmd = struct.unpack(">H", data[12:14])[0]
    plen = struct.unpack(">H", data[14:16])[0]
    if plen > 65535:
        return None, None, data
    if len(data) >= 16 + plen:
        return cmd, data[16:16 + plen], data[16 + plen:]
    return None, None, data


# ── REQVIP 载荷解析 ──────────────────────────────────────
def _parse_ip(b):
    return ".".join(str(x) for x in b)

def parse_netcfg(payload):
    """从 REQVIP 响应载荷中提取 VIP/掩码/DNS/路由，基于日志中的字段偏移"""
    if len(payload) < 30:
        return None

    vip = {
        "vip_ip": _parse_ip(payload[0:4]),
        "mask": _parse_ip(payload[4:8]),
        "dns": [],
        "routes": [],
    }

    # 从 DNS Server IP Nums 偏移附近扫描：找到第一个非零IP段视为 DNS
    for off in range(0x80, min(len(payload) - 4, 0xC0)):
        if payload[off:off + 2] != b"\x00\x00":
            try:
                candidate = _parse_ip(payload[off:off + 4])
                ipaddress.IPv4Address(candidate)
                if candidate not in vip["dns"]:
                    vip["dns"].append(candidate)
            except Exception:
                continue

    # 路由表从尾部向前扫描（net/mask 对，以 0xFF 终结）
    route_off = min(0xC0, len(payload) - 32)
    while route_off + 16 <= len(payload):
        net_b = payload[route_off:route_off + 4]
        mask_b = payload[route_off + 4:route_off + 8]
        if net_b == b"\xff\xff\xff\xff":
            break
        if net_b != b"\x00\x00\x00\x00":
            vip["routes"].append((_parse_ip(net_b), _parse_ip(mask_b)))
        route_off += 16

    return vip


def probe_gateway(host, ip, ctx1f4):
    t0 = time.time()
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, 4433), timeout=5)
        s = ssl_ctx.wrap_socket(raw, server_hostname=host)
        s.settimeout(5)
        s.sendall(cnem_frame(CMD_ACL, extra_be32=0, ctx1f4=ctx1f4))
        r = s.recv(4096)
        if struct.unpack(">H", r[12:14])[0] != CMD_ACL:
            s.close()
            return None
        s.sendall(cnem_frame(CMD_REQVIP, ctx1f4=ctx1f4))
        buf = b""
        try:
            for _ in range(3):
                d = s.recv(65536)
                if not d:
                    break
                buf += d
        except Exception:
            pass
        s.close()
        lat = (time.time() - t0) * 1000
        if len(buf) < 30:
            return None
        _, payload, _ = parse_cnem(buf)
        if not payload:
            return None
        netcfg = parse_netcfg(payload)
        if not netcfg:
            return None
        return {"host": host, "ip": ip, "latency": lat, **netcfg}
    except Exception:
        return None


def select_gateway(sess, gateways):
    ctx1f4 = int(sess["user_id"])
    print("[*] 探测网关...")
    results = []
    with ThreadPoolExecutor(max_workers=min(len(gateways), 8)) as pool:
        futures = {pool.submit(probe_gateway, h, ip, ctx1f4): h for h, ip in gateways}
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)
    if not results:
        print("[!] 所有网关不可达")
        sys.exit(1)
    results.sort(key=lambda r: r["latency"])
    for r in results:
        print(f"  {r['host']}: {r['latency']:.0f}ms → VIP={r['vip_ip']}")
    return results[0]


def create_tun(name="cnem0"):
    TUNSETIFF = 0x400454CA
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), 0x0001 | 0x1000)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd, name


def run_cmd(args):
    """安全运行系统命令"""
    subprocess.run(args, check=False, capture_output=True)


def main():
    if os.geteuid() != 0:
        print("需要 root 权限 (TUN)")
        sys.exit(1)

    config = load_config()
    if not config["gateways"]:
        print("[!] 未配置, 进入设置向导...\n")
        if not setup_wizard():
            sys.exit(1)
        config = load_config()

    if not os.path.exists(SESSION_FILE):
        print("[!] 无会话, 请先运行: python3 auth.py")
        sys.exit(1)

    with open(SESSION_FILE) as f:
        sess = json.load(f)
    ctx1f4 = int(sess["user_id"])
    gateways = config["gateways"]
    tun_name = config["tun_name"]

    vip = select_gateway(sess, gateways)
    host, ip = vip["host"], vip["ip"]

    # ── TLS 连接 ──
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, 4433), timeout=15)
    sock = ssl_ctx.wrap_socket(raw, server_hostname=host)
    sock.settimeout(30)
    sock.sendall(cnem_frame(CMD_ACL, extra_be32=0, ctx1f4=ctx1f4))
    sock.recv(4096)
    sock.sendall(cnem_frame(CMD_REQVIP, ctx1f4=ctx1f4))
    buf = b""
    try:
        sock.settimeout(5)
        for _ in range(3):
            d = sock.recv(65536)
            if not d:
                break
            buf += d
    except Exception:
        pass
    sock.settimeout(30)

    # ── TUN 配置 ──
    tun_fd, tun_name = create_tun(tun_name)
    run_cmd(["ip", "link", "set", tun_name, "up"])
    run_cmd(["ip", "addr", "add", f"{vip['vip_ip']}/24", "dev", tun_name])
    for net, mask in vip["routes"]:
        prefix = ipaddress.IPv4Network(f"{net}/{mask}", strict=False).prefixlen
        run_cmd(["ip", "route", "add", f"{net}/{prefix}", "dev", tun_name])
    for subnet in ["10.11.0.0/16", "10.12.0.0/16", "10.13.0.0/16", "192.168.0.0/16"]:
        run_cmd(["ip", "route", "add", subnet, "dev", tun_name])
    if vip["dns"]:
        with open("/tmp/cnem_resolv.conf", "w") as f:
            f.write(f"nameserver {vip['dns'][0]}\n")

    print(f"\n[*] {host} ({vip['latency']:.0f}ms) VIP={vip['vip_ip']} DNS={vip['dns']}")
    print(f"    TUN: {tun_name}  Ctrl+C 停止")

    # ── 双向转发 + 心跳 ──
    running = True
    last_keepalive = time.time()
    sock_lock = threading.Lock()

    def send_keepalive():
        """每 30s 发送心跳帧，防止网关踢连接"""
        nonlocal last_keepalive
        while running:
            time.sleep(10)
            if time.time() - last_keepalive >= 30:
                try:
                    with sock_lock:
                        sock.sendall(KEEPALIVE_FRAME)
                    last_keepalive = time.time()
                except Exception:
                    break

    def tun_to_tls():
        nonlocal last_keepalive
        while running:
            r, _, _ = select.select([tun_fd], [], [], 1)
            if r:
                try:
                    packet = os.read(tun_fd, 65536)
                    if packet:
                        with sock_lock:
                            sock.sendall(cnem_frame(CMD_DATA, packet, ctx1f4=ctx1f4))
                        last_keepalive = time.time()
                except OSError as e:
                    print(f"  [!] TUN读取错误: {e}")
                    break
                except Exception as e:
                    print(f"  [!] TLS写入错误: {e}")
                    break

    def tls_to_tun():
        buf = b""
        while running:
            try:
                data = sock.recv(65536)
                if not data:
                    print("  [!] TLS连接关闭")
                    break
                buf += data
                while len(buf) >= 16:
                    cmd, payload, remaining = parse_cnem(buf)
                    if cmd is None:
                        break
                    buf = remaining
                    if cmd == CMD_DATA and payload:
                        os.write(tun_fd, payload)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"  [!] TLS读取错误: {e}")
                break

    t1 = threading.Thread(target=tun_to_tls, daemon=True)
    t2 = threading.Thread(target=tls_to_tun, daemon=True)
    t3 = threading.Thread(target=send_keepalive, daemon=True)
    t1.start()
    t2.start()
    t3.start()

    try:
        while t1.is_alive() and t2.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        running = False
        sock.close()
        os.close(tun_fd)
        run_cmd(["ip", "link", "del", tun_name])
        print("已清理")


if __name__ == "__main__":
    main()
