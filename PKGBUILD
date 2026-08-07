# Maintainer: OpenUniVPN
pkgname=openunivpn
pkgver=0.1.0
pkgrel=3
pkgdesc="H3C SecPath SSLVPN 开源替代客户端"
arch=('any')
url="https://github.com/example/openunivpn"
license=('custom')
depends=('python>=3.8')
makedepends=('git')
source=("git+https://github.com/example/openunivpn.git#tag=v$pkgver")
sha256sums=('SKIP')
install="$pkgname.install"

package() {
    cd "$srcdir/$pkgname"

    # 主程序
    install -Dm644 auth.py client.py config.py protocol-format.md README.md -t "$pkgdir/opt/$pkgname/"
    install -Dm644 tools/mitm_proxy.py -t "$pkgdir/opt/$pkgname/tools/"

    # 系统配置模板
    install -Dm644 /dev/stdin "$pkgdir/etc/$pkgname/config.conf" << 'EOF'
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
