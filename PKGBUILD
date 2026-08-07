# Maintainer: OpenUniVPN
pkgname=openunivpn
pkgver=0.1.0
pkgrel=3
pkgdesc="H3C SecPath SSLVPN 开源替代客户端"
arch=('any')
url="https://github.com/tsaitang404/openunivpn"
license=('MIT')
depends=('python>=3.8' 'openresolv')
makedepends=('git')
source=("${pkgname}::git+${url}.git#tag=v${pkgver}")
sha256sums=('SKIP')
install="$pkgname.install"

package() {
    cd "$srcdir/$pkgname"

    # 主程序
    install -Dm644 client.py config.py protocol-format.md README.md -t "$pkgdir/opt/$pkgname/"

    # systemd service
    install -Dm644 openunivpn.service -t "$pkgdir/usr/lib/systemd/system/"

    # 系统配置模板（占位，需手动填写凭据）
    install -Dm600 /dev/stdin "$pkgdir/etc/$pkgname/config.conf" << 'EOF'
# OpenUniVPN 系统级配置模板
# 拷贝到 /etc/openunivpn/config.conf 后填写凭据，权限应保持 600

[auth]
username =
password =

[gateway]
# 格式: host:ip,host:ip
list =

[tun]
name = cnem0
EOF

    # 会话目录
    install -dm755 "$pkgdir/var/lib/$pkgname"

    # 许可证
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
