# OpenUniVPN — H3C SecPath SSLVPN 开源替代客户端

第三方实现的 UniVPN 协议客户端，支持多网关自动选路。

## 安装

```bash
git clone <repo> /opt/openunivpn
sudo mkdir -p /etc/openunivpn /var/lib/openunivpn
sudo cp /opt/openunivpn/.env.example /etc/openunivpn/.env
# 编辑 /etc/openunivpn/.env 填入凭据和网关列表
```

## 配置 `/etc/openunivpn/.env`

```ini
USERNAME=<用户名>
PASSWORD=<密码>
GATEWAYS=<站点1>:<IP1>,<站点2>:<IP2>
```

## 使用

```bash
python3 auth.py              # 认证并保存会话
sudo python3 client.py        # 启动 VPN (TUN 模式)
```

## 文件结构

```
/etc/openunivpn/.env          # 配置文件
/var/lib/openunivpn/          # 会话数据
/opt/openunivpn/
├── auth.py                   # Web 认证
├── client.py                 # VPN 客户端
├── config.py                 # 配置加载
├── protocol-format.md        # 协议文档
├── tools/mitm_proxy.py       # MITM 调试代理
```

## 依赖

Python 3.8+，标准库。

## License

仅供研究学习用途。
