#!/usr/bin/env python3
"""
UniVPN 开源客户端 — 自动选最优网关 + TUN 模式

用法:
  1. python3 auth.py                     # Web 认证
  2. sudo python3 client.py              # 启动 VPN (自动选最快网关)
  3. dae 分流内网段到 cnem0 / 浏览器直接访问内网 IP
"""
import socket, ssl, struct, json, base64, sys, os, time, threading, select, fcntl
from config import load_config, setup_wizard, SESSION_FILE, DATA_DIR

CNEM_MAGIC = 0xBEEFFCFE
CNEM_SESSION = 0xD6A492C1
CMD_ACL = 0x0006
CMD_REQVIP = 0x0003
CMD_DATA = 0x0002

be32 = lambda v: struct.pack(">I", v & 0xFFFFFFFF)
be16 = lambda v: struct.pack(">H", v & 0xFFFF)
MAGIC_B = struct.pack("<I", CNEM_MAGIC)
SESS_B  = struct.pack("<I", CNEM_SESSION)

def cnem_frame(cmd, payload=b"", ctx1f4=0, extra_be32=None):
    if extra_be32 is not None:
        payload = payload + be32(extra_be32)
    return MAGIC_B + SESS_B + be32(ctx1f4) + be16(cmd) + be16(len(payload)) + payload

def parse_cnem(data):
    if len(data) < 16: return None, None, data
    cmd = struct.unpack(">H", data[12:14])[0]
    plen = struct.unpack(">H", data[14:16])[0]
    if plen > 10000: return None, None, data
    payload = data[16:16+plen] if len(data) >= 16+plen else data[16:]
    return cmd, payload, data[16+plen:]

def probe_gateway(host, ip, ctx1f4):
    t0 = time.time()
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, 4433), timeout=5)
        s = ssl_ctx.wrap_socket(raw, server_hostname=host); s.settimeout(5)
        s.sendall(cnem_frame(CMD_ACL, extra_be32=0, ctx1f4=ctx1f4))
        r = s.recv(4096)
        if struct.unpack(">H", r[12:14])[0] != CMD_ACL:
            s.close(); return None
        s.sendall(cnem_frame(CMD_REQVIP, ctx1f4=ctx1f4))
        buf = b""
        try:
            for _ in range(3):
                d = s.recv(65536)
                if not d: break
                buf += d
        except: pass
        s.close()
        lat = (time.time() - t0) * 1000
        if len(buf) < 30: return None
        _, payload, _ = parse_cnem(buf)
        if not payload: return None
        vip = {
            'host': host, 'ip': ip, 'latency': lat,
            'vip_ip': '.'.join(str(b) for b in payload[0:4]),
            'mask': '.'.join(str(b) for b in payload[4:8]),
            'dns': [], 'routes': []
        }
        if len(payload) > 0xa4:
            vip['dns'].append('.'.join(str(b) for b in payload[0xa0:0xa4]))
            vip['dns'].append('.'.join(str(b) for b in payload[0xa4:0xa8]))
        offset = 0xc0
        while offset + 16 <= len(payload):
            net = payload[offset:offset+4]; mask = payload[offset+4:offset+8]
            if net == b'\xff\xff\xff\xff': break
            if net != b'\x00\x00\x00\x00':
                vip['routes'].append(('.'.join(str(b) for b in net), '.'.join(str(b) for b in mask)))
            offset += 16
        return vip
    except: return None

def select_gateway(sess, gateways):
    ctx1f4 = int(sess['user_id'])
    print("[*] 探测网关...")
    results = []
    threads = []
    for host, ip in gateways:
        t = threading.Thread(target=lambda h,i,c: results.append(probe_gateway(h,i,c)),
                             args=(host, ip, ctx1f4))
        t.start(); threads.append(t)
    for t in threads: t.join(timeout=10)
    results = [r for r in results if r]
    if not results:
        print("[!] 所有网关不可达"); sys.exit(1)
    results.sort(key=lambda r: r['latency'])
    for r in results:
        print(f"  {r['host']}: {r['latency']:.0f}ms → VIP={r['vip_ip']}")
    return results[0]

def create_tun(name="cnem0"):
    TUNSETIFF = 0x400454ca
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), 0x0001 | 0x1000)  # IFF_TUN | IFF_NO_PI
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd, name

def main():
    if os.geteuid() != 0:
        print("需要 root 权限 (TUN)"); sys.exit(1)

    config = load_config()
    if not config['gateways']:
        print("[!] 未配置, 进入设置向导...\n")
        if not setup_wizard():
            sys.exit(1)
        config = load_config()

    if not os.path.exists(SESSION_FILE):
        print("[!] 无会话, 请先运行: python3 auth.py")
        sys.exit(1)

    with open(SESSION_FILE) as f: sess = json.load(f)
    ctx1f4 = int(sess['user_id'])
    gateways = config['gateways']
    tun_name = config['tun_name']

    vip = select_gateway(sess, gateways)
    host, ip = vip['host'], vip['ip']

    # 最终连接
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False; ssl_ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, 4433), timeout=15)
    sock = ssl_ctx.wrap_socket(raw, server_hostname=host); sock.settimeout(30)
    sock.sendall(cnem_frame(CMD_ACL, extra_be32=0, ctx1f4=ctx1f4))
    sock.recv(4096)
    sock.sendall(cnem_frame(CMD_REQVIP, ctx1f4=ctx1f4))
    buf = b""
    try:
        sock.settimeout(5)
        for _ in range(3):
            d = sock.recv(65536)
            if not d: break; buf += d
    except: pass
    sock.settimeout(30)

    # TUN
    tun_fd, tun_name = create_tun()
    os.system(f"ip link set {tun_name} up")
    os.system(f"ip addr add {vip['vip_ip']}/24 dev {tun_name}")
    for net, _ in vip['routes']:
        os.system(f"ip route add {net}/24 dev {tun_name} 2>/dev/null")
    # 兜底：网关下发的内网段
    for subnet in ['10.11.0.0/16', '10.12.0.0/16', '10.13.0.0/16', '192.168.0.0/16']:
        os.system(f"ip route add {subnet} dev {tun_name} 2>/dev/null")
    if vip['dns']:
        os.system(f"echo 'nameserver {vip['dns'][0]}' > /tmp/cnem_resolv.conf 2>/dev/null")

    print(f"\n[*] {host} ({vip['latency']:.0f}ms) VIP={vip['vip_ip']} DNS={vip['dns']}")
    print(f"    TUN: {tun_name}  Ctrl+C 停止")

    # 转发
    running = True
    def tun_to_tls():
        while running:
            r, _, _ = select.select([tun_fd], [], [], 1)
            if r:
                try:
                    packet = os.read(tun_fd, 65536)
                    if packet:
                        sock.sendall(cnem_frame(CMD_DATA, packet, ctx1f4=ctx1f4))
                except: break

    def tls_to_tun():
        buf = b""
        while running:
            try:
                data = sock.recv(65536)
                if not data: break
                buf += data
                while len(buf) >= 16:
                    cmd, payload, remaining = parse_cnem(buf)
                    if cmd is None: break
                    buf = remaining
                    if cmd == CMD_DATA and payload:
                        os.write(tun_fd, payload)
            except socket.timeout: continue
            except: break

    t1 = threading.Thread(target=tun_to_tls, daemon=True)
    t2 = threading.Thread(target=tls_to_tun, daemon=True)
    t1.start(); t2.start()
    try:
        while t1.is_alive() and t2.is_alive(): time.sleep(0.5)
    except KeyboardInterrupt: pass
    finally:
        running = False; sock.close(); os.close(tun_fd)
        os.system(f"ip link del {tun_name} 2>/dev/null"); print("已清理")

if __name__ == "__main__":
    main()
