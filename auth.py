#!/usr/bin/env python3
"""OpenUniVPN Web 认证 — 自动尝试所有网关, 保存会话"""

import http.client, ssl, re, json, sys, os, urllib.parse, logging
from config import load_config, setup_wizard, SESSION_FILE, DATA_DIR

logger = logging.getLogger('openunivpn')


class H3CUniVPNAuth:
    def __init__(self, gateway, gateway_ip, port=4433, username='', password=''):
        self.gateway = gateway
        self.gateway_ip = gateway_ip
        self.port = port
        self.username = username
        self.password = password
        self.cookies = {}
        self.csrf_tk = None
        self.user_id = None
        self.session_id = None
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method, path, headers=None, body=None):
        conn = http.client.HTTPSConnection(self.gateway_ip, self.port, context=self.ctx, timeout=15)
        all_headers = {"Host": f"{self.gateway}:{self.port}"}
        if self.cookies:
            all_headers["Cookie"] = self._cookie_str()
        if headers:
            all_headers.update(headers)
        conn.request(method, path, body=body, headers=all_headers)
        resp = conn.getresponse()
        data = resp.read()
        set_cookie = resp.getheader("Set-Cookie")
        if set_cookie:
            self._parse_set_cookie(set_cookie)
        location = resp.getheader("Location")
        conn.close()
        return resp.status, dict(resp.getheaders()), data, location

    def _parse_set_cookie(self, set_cookie):
        for part in set_cookie.split(";"):
            part = part.strip()
            if part.startswith("UserID="):
                m = re.match(r"UserID=(\d+)&SVN_SessionID=([^;]+)", part)
                if m:
                    self.user_id = m.group(1)
                    self.session_id = m.group(2)
                    self.cookies["UserID"] = part.split("=", 1)[1]
                    return
        if "=" in set_cookie:
            k, v = set_cookie.split("=", 1)
            self.cookies[k.strip()] = v.split(";")[0].strip()

    def _cookie_str(self):
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def login(self):
        logger.info("[%s] 认证...", self.gateway)
        status, _, _, location = self._request("GET", "/login.html")
        if location and "CsrfTk=" in location:
            m = re.search(r"CsrfTk=([^&]+)", location)
            if m:
                self.csrf_tk = m.group(1)

        form = urllib.parse.urlencode({
            "UserName": self.username, "Password": self.password,
            "MacAddress": "FFFF-FFFF-FFFF", "SVN_Seco_AaA": "1",
            "SelectLanguage": "0", "VerificationCode": "", "VerificationCodeId": "", "aaa": "1",
        })
        status, headers, body, location = self._request(
            "POST", "/login.html",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=form,
        )
        if location and "main.html" in location:
            if not self.user_id or not self.session_id:
                logger.warning("[%s] 登录成功但未提取到 UserID/SessionID（Cookie 格式可能变更）",
                               self.gateway)
                return False
            logger.info("[%s] ✓ UserID=%s", self.gateway, self.user_id)
            return True
        # 判断登录失败原因
        body_str = body.decode("utf-8", errors="replace")
        if "密码不正确" in body_str or "password" in body_str.lower():
            logger.warning("[%s] ✗ 密码错误", self.gateway)
        elif "用户不存在" in body_str or "user" in body_str.lower():
            logger.warning("[%s] ✗ 用户不存在", self.gateway)
        else:
            logger.warning("[%s] ✗ 登录失败 (HTTP %s)", self.gateway, status)
        return False

    def get_session(self):
        return {
            "gateway": self.gateway, "gateway_ip": self.gateway_ip,
            "port": self.port, "user_id": self.user_id,
            "session_id": self.session_id, "csrf_tk": self.csrf_tk,
        }


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )

    config = load_config()
    username = config['username']
    password = config['password']
    gateways = config['gateways']

    if not gateways:
        # systemd 非交互环境下 setup_wizard 会立即返回 False
        print("[!] 未配置, 进入设置向导...\n")
        if not setup_wizard():
            sys.exit(1)
        config = load_config()
        username = config['username']
        password = config['password']
        gateways = config['gateways']

    for host, ip in gateways:
        auth = H3CUniVPNAuth(host, ip, 4433, username, password)
        try:
            if auth.login():
                os.makedirs(DATA_DIR, exist_ok=True)
                # session.json 含 UserID/SessionID，等价于会话凭据，限制权限
                with open(SESSION_FILE, "w") as f:
                    json.dump(auth.get_session(), f, indent=2)
                os.chmod(SESSION_FILE, 0o600)
                print(f"\n会话已保存 ({host})")
                return 0
        except Exception as e:
            logger.warning("[%s] ✗ %s", host, e)

    logger.error("所有网关认证失败")
    return 1


if __name__ == "__main__":
    sys.exit(main())
