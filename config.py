"""OpenUniVPN 配置管理

配置文件路径 (优先级):
  1. 环境变量 OPENUNIVPN_CONFIG
  2. ~/.config/openunivpn/config.conf  (用户级)
  3. /etc/openunivpn/config.conf       (系统级)

会话文件: ~/.local/share/openunivpn/session.json
"""

import os
import configparser

USER_CONFIG = os.path.expanduser('~/.config/openunivpn/config.conf')
SYSTEM_CONFIG = '/etc/openunivpn/config.conf'
DATA_DIR = os.path.expanduser('~/.local/share/openunivpn')
SESSION_FILE = os.path.join(DATA_DIR, 'session.json')


def _find_config():
    paths = [
        os.environ.get('OPENUNIVPN_CONFIG', ''),
        USER_CONFIG,
        SYSTEM_CONFIG,
    ]
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def _parse_config(path):
    """解析 INI 格式配置文件"""
    c = configparser.RawConfigParser()
    c.read(path)

    gateways_raw = c.get('gateway', 'list', fallback='')
    gateways = []
    if gateways_raw:
        for pair in gateways_raw.split(','):
            pair = pair.strip()
            if ':' in pair:
                host, ip = pair.split(':', 1)
                gateways.append((host.strip(), ip.strip()))

    return {
        'username': c.get('auth', 'username', fallback=''),
        'password': c.get('auth', 'password', fallback=''),
        'gateways': gateways,
        'tun_name': c.get('tun', 'name', fallback='cnem0'),
    }


def load_config():
    path = _find_config()
    if path:
        return _parse_config(path)
    return {'username': '', 'password': '', 'gateways': [], 'tun_name': 'cnem0'}


def setup_wizard():
    """交互式配置向导"""
    import shutil

    os.makedirs(os.path.dirname(USER_CONFIG), exist_ok=True)

    print("OpenUniVPN — 首次配置\n")

    username = input("用户名: ").strip()
    password = input("密码: ").strip()
    print()

    print("网关列表 (每行一个, 格式: host:ip, 空行结束)")
    print("  例: vpn.example.com:1.2.3.4")
    gateways = []
    while True:
        line = input(f"  网关 #{len(gateways)+1}: ").strip()
        if not line:
            break
        if ':' in line:
            gateways.append(line)

    if not gateways:
        print("[!] 至少需要一个网关")
        return False

    # 写入配置
    c = configparser.RawConfigParser()
    c['auth'] = {'username': username, 'password': password}
    c['gateway'] = {'list': ','.join(gateways)}
    c['tun'] = {'name': 'cnem0'}

    with open(USER_CONFIG, 'w') as f:
        c.write(f)

    # 创建数据目录
    os.makedirs(DATA_DIR, exist_ok=True)

    # 也写一份 .env.example 模板
    example = os.path.join(os.path.dirname(USER_CONFIG), 'config.example.conf')
    if not os.path.exists(example):
        shutil.copy(USER_CONFIG, example)
        print(f"\n配置模板: {example}")

    print(f"\n✓ 配置已保存: {USER_CONFIG}")
    return True
