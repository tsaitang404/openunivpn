"""Opt-in exclusive upstream switching for a local dnsmasq."""
import ipaddress
import json
import os
import subprocess
import tempfile
from pathlib import Path

ACTIVE = Path('/run/openunivpn-dns.servers')
OFFLINE = Path('/etc/openunivpn/dnsmasq-offline.servers')


def reload_dnsmasq():
    subprocess.run(['/usr/bin/systemctl', 'reload', 'dnsmasq.service'], check=True, timeout=15)


def replace_active(content=None):
    with tempfile.TemporaryDirectory(dir=ACTIVE.parent, prefix='.openunivpn-dns-') as directory:
        staged = Path(directory) / 'servers'
        if content is None:
            staged.symlink_to(OFFLINE)
        else:
            staged.write_text(content, encoding='ascii')
            staged.chmod(0o644)
        os.replace(staged, ACTIVE)


def routed_to_tunnel(ip, tun_name):
    if not tun_name:
        return False
    result = subprocess.run(['/usr/bin/ip', '-j', 'route', 'get', str(ip)],
                            capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        return False
    routes = json.loads(result.stdout)
    return (len(routes) == 1 and routes[0].get('dev') == tun_name
            and routes[0].get('type', 'unicast') == 'unicast')


def tunnel_dns_servers(addresses, tun_name):
    servers = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.version != 4 or ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip in servers:
            continue
        if routed_to_tunnel(ip, tun_name):
            servers.append(ip)
    return servers


def activate(addresses, tun_name, *, before_change=None):
    servers = tunnel_dns_servers(addresses, tun_name)
    if not servers:
        return False
    if not OFFLINE.is_file() or not ACTIVE.is_symlink() or Path(os.readlink(ACTIVE)) != OFFLINE:
        raise OSError('dnsmasq integration not ready: expected the offline servers file and its runtime symlink')
    if before_change is not None:
        before_change()
    replace_active(''.join(f'server={ip}\n' for ip in servers))
    try:
        reload_dnsmasq()
    except (OSError, subprocess.SubprocessError):
        if before_change is None:
            restore()
        raise
    return True


def restore(*, required=False):
    if ACTIVE.is_symlink():
        if Path(os.readlink(ACTIVE)) != OFFLINE or not OFFLINE.is_file():
            if required:
                raise OSError('dnsmasq offline servers symlink is invalid')
            return
    elif ACTIVE.is_file():
        if not OFFLINE.is_file():
            raise OSError('dnsmasq offline servers file is missing')
        replace_active()
    else:
        if required:
            raise OSError('dnsmasq runtime servers file is missing')
        return
    # Retry reload even after an earlier attempt restored the symlink.
    reload_dnsmasq()


if __name__ == '__main__':
    restore()
