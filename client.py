#!/usr/bin/env python3
"""
UniVPN 开源客户端 — 自动选最优网关 + TUN 模式

用法:
  1. python3 auth.py                     # Web 认证
  2. sudo python3 client.py              # 启动 VPN (自动选最快网关)
  3. dae 分流内网段到 cnem0 / 浏览器直接访问内网 IP
"""
import socket, ssl, struct, json, sys, os, time, threading, select, fcntl, subprocess, ipaddress, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import load_config, setup_wizard, SESSION_FILE, DATA_DIR

logger = logging.getLogger('openunivpn')

# ── CNEM 协议常量 ──────────────────────────────────────
# 详见 protocol-format.md
# 命令分发表（HTML 报告 §3.3，二进制偏移 0x458aa8）：
#   0x02 数据帧, 0x03 REQVIP, 0x05 REQVIP V1, 0x06 UdpPort 响应,
#   0x07 V1 UDP 探测, 0x0d UDP_AVAILABLE, 0x1a DATA_CONNECT
CNEM_MAGIC = 0xBEEFFCFE
CNEM_SESSION = 0xD6A492C1
CMD_ACL = 0x0006         # §3.2 ACL 请求（连接后第 1 帧）
CMD_REQVIP = 0x0003      # REQVIP 请求（GmAlgorithm=0 当前网关，载荷长度=0；2026-08-07 最终验证）
CMD_DATA = 0x0002
CMD_KEEPALIVE = 0x0005

# 心跳参数
KEEPALIVE_CHECK_INTERVAL = 10   # 检查间隔（秒）
KEEPALIVE_IDLE_TIMEOUT = 30     # 距上次发包超过此值则发心跳


def be32(v):
    """大端 32 位打包"""
    return struct.pack(">I", v & 0xFFFFFFFF)


def be16(v):
    """大端 16 位打包"""
    return struct.pack(">H", v & 0xFFFF)


MAGIC_B = struct.pack("<I", CNEM_MAGIC)
SESS_B = struct.pack("<I", CNEM_SESSION)

KEEPALIVE_FRAME = MAGIC_B + SESS_B + be32(0) + be16(CMD_KEEPALIVE) + be16(0)


def cnem_frame(cmd, payload=b"", ctx1f4=0, extra_be32=None):
    """构造 CNEM 帧（16 字节帧头 + 可选载荷）

    帧格式（详见 protocol-format.md §3.1）：
      +0   u32 LE  magic
      +4   u32 LE  session[0..3]
      +8   u32 BE  ctx1f4 (网络字节序)
      +12  u16 BE  cmd
      +14  u16 BE  payload 长度
      +16  ...     payload
    """
    if extra_be32 is not None:
        payload = payload + be32(extra_be32)
    return MAGIC_B + SESS_B + be32(ctx1f4) + be16(cmd) + be16(len(payload)) + payload


def parse_cnem(data):
    """解析 CNEM 帧，返回 (cmd, payload, remaining)。

    若数据不完整返回 (None, None, 原始 data)，由调用方继续缓冲。

    ⚠ len 字段端序：实测网关响应中 ACL(cmd=0x0006) 用**小端**（`14 00`=20），
    REQVIP(cmd=0x0003) 用**大端**（`03 bc`=956）。发送方向恒用大端（网关接受）。
    因此这里对响应帧做自适应：BE/LE 都试，取能恰好覆盖缓冲长度者。
    """
    if len(data) < 16:
        return None, None, data
    cmd = struct.unpack(">H", data[12:14])[0]
    plen_be = struct.unpack(">H", data[14:16])[0]
    plen_le = struct.unpack("<H", data[14:16])[0]
    # 优先选能恰好覆盖缓冲的端序；两端序都不完整则返回 None 继续缓冲
    for plen in sorted({plen_be, plen_le}):
        if plen <= 65535 and 16 + plen <= len(data):
            return cmd, data[16:16 + plen], data[16 + plen:]
    return None, None, data


# ── REQVIP 响应解析 ──────────────────────────────────
# 结构（2026-08-07 实测，bjvpn.canway.net, payload=956B）：
#   @0   4B  VIP
#   @4   4B  掩码
#   @8   4B  保留
#   ...  中间为随机/加密数据（约 @8-159）
#   @160 4B  DNS 服务器 1
#   @164 4B  DNS 服务器 2
#   @168 16B 零填充
#   @186 2B  BE 路由数量
#   @188 ... 路由表，每条 12B：network(4B) + mask(4B) + extra(4B)
# ⚠ 偏移基于本网关固件实测，若固件升级结构变化需重新校准
#   （对照 protocol-format.md §4 和 HTML 逆向报告）

NETCFG_DNS_OFF = 0xA0        # 160
NETCFG_RT_COUNT_OFF = 0xBA   # 186
NETCFG_RT_START = 0xBC       # 188
NETCFG_RT_STRIDE = 12

def _parse_ip(b):
    return ".".join(str(x) for x in b)

def parse_netcfg(payload):
    """从 REQVIP 响应载荷中提取 VIP/掩码/DNS/路由（精确偏移解析）。"""
    if len(payload) < 30:
        logger.warning("REQVIP 响应过短 (%d 字节)，无法解析", len(payload))
        return None

    vip = {
        "vip_ip": _parse_ip(payload[0:4]),
        "mask": _parse_ip(payload[4:8]),
        "dns": [],
        "routes": [],
    }
    logger.debug("REQVIP netcfg 载荷=%dB VIP=%s mask=%s",
                 len(payload), vip["vip_ip"], vip["mask"])

    # DNS：@160/164 两个连续 IP（跳过 0.0.0.0）
    for off in (NETCFG_DNS_OFF, NETCFG_DNS_OFF + 4):
        if off + 4 <= len(payload):
            candidate = _parse_ip(payload[off:off + 4])
            if candidate != "0.0.0.0":
                vip["dns"].append(candidate)
    if not vip["dns"]:
        logger.warning("未能从 REQVIP 响应解析出 DNS（偏移可能已漂移）")

    # 路由表：@188 开始，每条 12B，数量由 @184 给出
    if NETCFG_RT_COUNT_OFF + 2 <= len(payload):
        route_count = struct.unpack(">H", payload[NETCFG_RT_COUNT_OFF:NETCFG_RT_COUNT_OFF + 2])[0]
        off = NETCFG_RT_START
        for _ in range(route_count):
            if off + 8 > len(payload):
                break
            net_b = payload[off:off + 4]
            mask_b = payload[off + 4:off + 8]
            if net_b == b"\x00\x00\x00\x00" and mask_b == b"\x00\x00\x00\x00":
                break
            vip["routes"].append((_parse_ip(net_b), _parse_ip(mask_b)))
            off += NETCFG_RT_STRIDE

    logger.info("REQVIP 解析: VIP=%s mask=%s DNS=%s routes=%d",
                vip["vip_ip"], vip["mask"], vip["dns"], len(vip["routes"]))
    return vip


def probe_gateway(host, ip, ctx1f4):
    """只测 TCP 连通延迟（不建 TLS、不发业务帧）。

    重要：不能在此建立 TLS 连接或发送任何 CNEM 帧。
    网关对同一会话的裸 TLS 连接（握手后不发协议帧就关闭）敏感，
    会判定异常并对后续主连接返回 KICKOUT (cmd=0x0008)。
    因此探测只做 TCP connect 测延迟，完整握手仅在 main() 中做一次。
    """
    t0 = time.time()
    try:
        raw = socket.create_connection((ip, 4433), timeout=5)
        raw.close()
        lat = (time.time() - t0) * 1000
        return {"host": host, "ip": ip, "latency": lat}
    except Exception:
        return None


def select_gateway(ctx1f4, gateways):
    """并发探测所有网关（仅 TCP/TLS 连通性），按延迟升序返回最快的一个"""
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
        print(f"  {r['host']}: {r['latency']:.0f}ms")
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
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )

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

    gw = select_gateway(ctx1f4, gateways)
    host, ip, latency = gw["host"], gw["ip"], gw["latency"]

    # ── TLS 连接 + 完整握手（ACL → REQVIP）──
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, 4433), timeout=15)
    sock = ssl_ctx.wrap_socket(raw, server_hostname=host)
    sock.settimeout(30)

    # 1. ACL（连接后第 1 帧，20B：16B 头 + 4B ctx+0x1f8）
    sock.sendall(cnem_frame(CMD_ACL, extra_be32=0, ctx1f4=ctx1f4))
    acl_resp = b""
    try:
        acl_resp = sock.recv(4096)
    except Exception:
        pass
    logger.info("ACL 响应 %dB: %s", len(acl_resp), acl_resp[:64].hex())
    acl_cmd, _, _ = parse_cnem(acl_resp)
    if acl_cmd != CMD_ACL:
        print(f"[!] ACL 握手失败 (resp cmd=0x{(acl_cmd or 0):04x}, {len(acl_resp)}B)")
        sys.exit(1)
    logger.info("ACL 握手成功")

    # 2. REQVIP（16B 帧头，无载荷）
    sock.sendall(cnem_frame(CMD_REQVIP, ctx1f4=ctx1f4))
    buf = b""
    try:
        sock.settimeout(5)
        for _ in range(5):
            d = sock.recv(65536)
            if not d:
                break
            buf += d
    except Exception:
        pass
    sock.settimeout(30)

    # 解析 REQVIP 响应：提取 VIP/掩码/DNS/路由
    vip = None
    off = 0
    while off + 16 <= len(buf):
        cmd, pl, rest = parse_cnem(buf[off:])
        if cmd is None:
            break
        if cmd == 0x0003 and len(pl) >= 30:
            vip = parse_netcfg(pl)
            if vip:
                logger.info("REQVIP 解析成功: VIP=%s mask=%s", vip["vip_ip"], vip["mask"])
            break
        off += 16 + len(pl)

    if not vip:
        print("[!] REQVIP 响应解析失败，无法继续")
        sys.exit(1)

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

    print(f"\n[*] {host} ({latency:.0f}ms) VIP={vip['vip_ip']} DNS={vip['dns']}")
    print(f"    TUN: {tun_name}  Ctrl+C 停止")

    # ── 双向转发 + 心跳 ──
    running = True
    last_keepalive = time.time()
    sock_lock = threading.Lock()

    def send_keepalive():
        """每 KEEPALIVE_CHECK_INTERVAL 秒检查一次，距上次发包超过
        KEEPALIVE_IDLE_TIMEOUT 秒则发送心跳帧，防止网关踢连接。

        注：last_keepalive 由多线程共享读写，依赖 GIL 保证单次赋值的原子性；
        偶发的"读到稍旧的值"只会导致心跳略延迟，不影响正确性。
        """
        nonlocal last_keepalive
        while running:
            time.sleep(KEEPALIVE_CHECK_INTERVAL)
            if time.time() - last_keepalive >= KEEPALIVE_IDLE_TIMEOUT:
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
