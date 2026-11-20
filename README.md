# OpenUniVPN — H3C SecPath SSLVPN 开源替代客户端

第三方实现的 UniVPN 协议客户端，支持多网关自动选路。

仅供研究学习用途（见 [LICENSE](LICENSE)）。

## 安装

### Arch Linux（AUR）

```bash
paru -S openunivpn        # 或 yay -S openunivpn
```

### 从源码运行

```bash
git clone https://github.com/tsaitang404/openunivpn.git /opt/openunivpn
cd /opt/openunivpn
```

## 配置

配置文件查找优先级（取第一个存在的）：

1. 环境变量 `OPENUNIVPN_CONFIG` 指向的路径
2. `~/.config/openunivpn/config.conf`（用户级）
3. `/etc/openunivpn/config.conf`（系统级，systemd 服务读取）

### 格式（INI）

```ini
[auth]
username = <用户名>
password = <密码>

[gateway]
# 格式: host:ip,host:ip  —— host 用于 TLS SNI，ip 用于实际连接
list = vpn.example.com:1.2.3.4,bjvpn.example.com:5.6.7.8

[tun]
name = cnem0
```

### 首次配置

手动编辑 `/etc/openunivpn/config.conf`（系统级）或 `~/.config/openunivpn/config.conf`（用户级），
填入用户名、密码和网关列表。建议权限设为 `600`（含明文密码）：

```bash
sudo chmod 600 /etc/openunivpn/config.conf
```

## 使用

```bash
sudo python3 /opt/openunivpn/client.py   # 启动 VPN（自动选最快网关 + TUN 模式）
```

或交给 systemd：

```bash
sudo systemctl enable --now openunivpn   # 开机自启 + 启动
sudo systemctl status openunivpn
sudo journalctl -u openunivpn -f          # 跟踪日志
```

## 文件结构

```
/etc/openunivpn/config.conf              # 系统级配置（含凭据，建议 600）
~/.config/openunivpn/config.conf         # 用户级配置
~/.local/share/openunivpn/session.json   # 会话缓存（含 UserID/SessionID）
/opt/openunivpn/
├── client.py                            # VPN 客户端（CNEM 协议 + TUN 转发）
├── config.py                            # 配置加载 + 交互式向导
└── protocol-format.md                   # 协议逆向文档
/usr/lib/systemd/system/openunivpn.service
```

## 依赖

Python 3.8+，仅标准库。

## License

[MIT](LICENSE) — 仅限研究和学习用途。本软件为 SSLVPN 协议的独立第三方实现，
与原厂无任何关联。用户自行承担使用本软件的一切风险和责任。

## 回归测试

```bash
python3 -m unittest discover -s tests -v
```

测试不读取认证配置，不建立 VPN 或修改网络。覆盖 DATA 的 IPv4/IPv6 长度校验、
两种帧长度端序、拆包/粘包、控制帧及接收循环的断连行为。

DATA 帧边界取自内层 IP 长度。ACL/REQVIP 使用已有捕获的长度端序；
UDP_AVAILABLE/DATA_CONNECT 的已知四字节响应支持两种端序。
其他控制帧长度若存在歧义，等待下一帧头确认边界；孤立的未知控制帧可能暂缓处理，
需新增协议捕获才能确定其格式。

## 网关切换与断线恢复

客户端每轮只用 TCP 探测网关，按连通延迟依次尝试。超时、连接关闭或重置等临时传输故障
才会切换到下一个网关；一轮耗尽后在同一进程内重新探测。退避以 3、6、12、24、48 秒递增，
带少量抖动且不超过 60 秒，可被停止信号打断。会话建立后重置退避。即使离线超过 systemd
的启动限流窗口，客户端仍会继续尝试。

明确的认证拒绝、TLS 证书校验失败、配置错误、KICKOUT 或无法识别的协议响应，会停止而不是
切换网关或重新认证。退出状态 `78` 不触发 systemd 自动重启；检查日志并修正原因后再手动启动。
证书失败不会自动关闭校验，也不会被当成密码错误。

空闲或业务流量没有回复不触发重连；控制连接仍正常时，客户端没有独立的数据面健康探测。

## 本机使用 dnsmasq 时的 DNS 接管

默认继续使用 openresolv。若系统通过本机 dnsmasq 解析，并且 dnsmasq 不使用 openresolv 写入的上游，可选用 `[dns]` 下的 `backend = dnsmasq`。此模式只更换 dnsmasq 上游，不更改网页流量路由。连接期间，公网域名也由 VPN DNS 解析。

启用前，由管理员一次性配置 dnsmasq：

1. 把原有 `server=` 上游（包括需在离线时保留的按域转发规则）移到 `/etc/openunivpn/dnsmasq-offline.servers`。确保该文件可被 dnsmasq 读取。移除仅为旧版 VPN 留下的临时转发，不要把它们放入离线文件。
2. 在 dnsmasq 中使用 `no-resolv` 和 `servers-file=/run/openunivpn-dns.servers`，不要保留其他静态或动态上游。不要移除本地 hosts、监听地址等非上游配置。
3. 在 `/etc/tmpfiles.d/openunivpn-dns.conf` 中写入 `L /run/openunivpn-dns.servers - - - - /etc/openunivpn/dnsmasq-offline.servers`，执行 `systemd-tmpfiles --create /etc/tmpfiles.d/openunivpn-dns.conf`。用 `dnsmasq --test` 验证，然后重启 dnsmasq。`dnsmasq.service` 必须支持用 SIGHUP 重读 `servers-file`。
4. 在 OpenUniVPN 配置中启用该后端，再启动 `openunivpn.service`。不要同时运行多个客户端实例。

两个 DNS 后端都默认校验 VPN 网关的 TLS 证书和主机名，且只采用经 VPN 隧道路由的 DNS 地址。使用企业 CA 的网关可在 `[gateway]` 中配置 `ca_file = /path/to/company-ca.pem`。仍需连接不受信网关时，可以显式设置 `[gateway]` 的 `tls_verify = false`，但此时不使用网关下发的 DNS：`dnsmasq` 要求在 `[dns]` 的 `servers` 填写受信的 VPN DNS IPv4 地址（逗号分隔）；`resolvconf` 可选填，未填写时保留系统 DNS。关闭校验可能使 VPN 凭据和流量被冒充网关截获，不影响浏览器的 HTTPS 校验。旧版 `resolvconf` 默认为不校验，升级前请检查网关证书配置。

断开时 OpenUniVPN 恢复离线上游；通过 systemd 运行时，异常退出也会执行恢复。若公司 DNS 本身超时，此模式不会改用公网 DNS；先验证 VPN 到公司 DNS 的连通性。
