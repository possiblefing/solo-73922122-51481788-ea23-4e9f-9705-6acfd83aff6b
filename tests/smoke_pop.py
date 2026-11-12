"""End-to-end smoke test for the PoP challenge/response flow.

Mirrors what the browser does:
  * generate a P-256 key (cryptography library, equivalent of Web Crypto)
  * login with the raw public key
  * fetch challenge -> sign (challenge, method, path) -> call signed endpoint
  * exercise replay, cross-purpose, bad-signature, cookie-only, logout paths

The test server runs as a real uvicorn *subprocess* (the same topology as the
docker deployment), so the restart section can terminate and re-exec it
against the same SQLite file.
"""
from __future__ import annotations

import base64
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

failures: list[str] = []


def check(cond: bool, label: str) -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
    if not cond:
        failures.append(label)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def build_message(challenge: str, method: str, path: str) -> bytes:
    out = bytearray()
    for part in (challenge.encode(), method.upper().encode(), path.encode()):
        out += f"{len(part)}:".encode() + part + b"|"
    return bytes(out)


class BrowserKey:
    """Equivalent of the non-extractable Web Crypto key + IndexedDB entry."""

    def __init__(self) -> None:
        self.priv = ec.generate_private_key(ec.SECP256R1())
        pub_raw = self.priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        self.public_key_b64 = b64url(pub_raw)

    def sign(self, challenge: str, method: str, path: str) -> str:
        der = self.priv.sign(build_message(challenge, method, path),
                             ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def signed_request(client: httpx.Client, key: BrowserKey, path: str,
                   purpose: str, method: str) -> httpx.Response:
    ch = client.post("/api/challenge", json={"purpose": purpose})
    assert ch.status_code == 200, ch.text
    challenge = ch.json()["challenge"]
    sig = key.sign(challenge, method, path)
    return client.request(
        method, path,
        headers={"X-Auth-Challenge": challenge, "X-Auth-Signature": sig},
    )


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="pop-smoke-")
    db_path = os.path.join(tmp, "login.db")
    os.environ["LOGIN_DB_PATH"] = db_path
    os.environ["PROCESS_NAME"] = "smoke"
    os.environ["ERROR_WINDOW_SECONDS"] = "60"
    os.environ["MAX_DELAY_SECONDS"] = "2"
    port = 8500 + (int(time.time()) % 100)

    # Import the application package once so a packaging/import error fails
    # the test fast instead of surfacing as an opaque subprocess timeout.
    import app.main  # noqa: F401,E402

    def start_server(p: int) -> subprocess.Popen:
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(p), "--log-level", "warning"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{p}/api/stats", timeout=2).status_code == 200:
                    return proc
            except httpx.TransportError:
                time.sleep(0.2)
        raise RuntimeError("test server never became ready")

    def stop_server(proc: subprocess.Popen) -> bool:
        """Best-effort stop; sandboxes may deny signals to child processes."""
        if proc.poll() is not None:
            return True
        try:
            proc.terminate()
            proc.wait(timeout=15)
            return True
        except (PermissionError, ProcessLookupError):
            return False
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=5)
                return True
            except PermissionError:
                return False

    server = start_server(port)
    base = f"http://127.0.0.1:{port}"
    live_servers = [server]
    try:
        key = BrowserKey()

        with httpx.Client(base_url=base, timeout=30) as c:
            print("1. 无会话访问")
            check(c.get("/api/me").status_code == 401, "GET /api/me 无 Cookie → 401")
            check(c.get("/api/me", headers={
                "X-Auth-Challenge": "x", "X-Auth-Signature": "y"}).status_code == 401,
                "带伪造签名头但无 Cookie → 401")
            check(c.post("/api/challenge", json={"purpose": "me"}).status_code == 401,
                  "无 Cookie 领挑战 → 401")

            print("2. 登录绑定公钥")
            r = c.post("/api/login", json={
                "username": "alice", "password": "alice-pass-2026",
                "public_key": key.public_key_b64})
            check(r.status_code == 200, f"正确密码+公钥登录 200（实际 {r.status_code} {r.text}）")
            check("session=" in r.headers.get("set-cookie", ""), "下发会话 Cookie")

            print("3. 仅 Cookie 无签名仍被拒")
            check(c.get("/api/me").status_code == 401, "GET /api/me 只带 Cookie → 401")

            print("4. 完整挑战-签名流程")
            r = signed_request(c, key, "/api/me", "me", "GET")
            check(r.status_code == 200 and r.json()["username"] == "alice",
                  f"签名调用 GET /api/me 200（实际 {r.status_code} {r.text}）")

            print("5. 挑战一次性：重放同一签名")
            ch = c.post("/api/challenge", json={"purpose": "me"}).json()["challenge"]
            sig = key.sign(ch, "GET", "/api/me")
            headers = {"X-Auth-Challenge": ch, "X-Auth-Signature": sig}
            r1 = c.get("/api/me", headers=headers)
            r2 = c.get("/api/me", headers=headers)
            check(r1.status_code == 200, "首次签名 200")
            check(r2.status_code == 401, f"重放同一挑战+签名 → 401（实际 {r2.status_code}）")

            print("6. 同挑战并发仅一次成功")
            ch = c.post("/api/challenge", json={"purpose": "me"}).json()["challenge"]
            sig = key.sign(ch, "GET", "/api/me")
            headers = {"X-Auth-Challenge": ch, "X-Auth-Signature": sig}

            def fire(_):
                # Dedicated client per thread: httpx cookie jars are not
                # guaranteed safe for concurrent mutation.
                with httpx.Client(base_url=base, timeout=30,
                                  cookies={"session": c.cookies["session"]}) as cc:
                    return cc.get("/api/me", headers=headers).status_code

            with ThreadPoolExecutor(max_workers=8) as pool:
                codes = list(pool.map(fire, range(8)))
            check(sorted(codes).count(200) == 1 and codes.count(401) == 7,
                  f"8 并发同一挑战：恰 1 个 200、7 个 401（实际 {sorted(codes)}）")

            print("7. 验签失败不消费挑战")
            ch = c.post("/api/challenge", json={"purpose": "me"}).json()["challenge"]
            fake_sig = b64url(b"\x01" * 64)
            check(c.get("/api/me", headers={
                "X-Auth-Challenge": ch, "X-Auth-Signature": fake_sig}).status_code == 401,
                "伪造签名 → 401")
            check(c.get("/api/me", headers={
                "X-Auth-Challenge": ch,
                "X-Auth-Signature": key.sign(ch, "GET", "/api/me")}).status_code == 200,
                "同一挑战在伪造签名后仍可用真签名成功（失败未消费）")

            print("8. 用途/方法/路径绑定")
            chm = c.post("/api/challenge", json={"purpose": "me"}).json()["challenge"]
            # me 挑战拿去调 logout（即使签名内容也是 me 的）
            r = c.post("/api/logout", headers={
                "X-Auth-Challenge": chm,
                "X-Auth-Signature": key.sign(chm, "GET", "/api/me")})
            check(r.status_code == 401, "me 挑战不能用于 logout → 401")
            # 为 me 挑战签 logout 的消息也不行
            r = c.post("/api/logout", headers={
                "X-Auth-Challenge": chm,
                "X-Auth-Signature": key.sign(chm, "POST", "/api/logout")})
            check(r.status_code == 401, "用途不匹配即使重签也 → 401")
            # 会话仍在
            check(signed_request(c, key, "/api/me", "me", "GET").status_code == 200,
                  "被拒后会话未受影响")

            print("9. 60 秒 TTL（用短 TTL 配置另测，这里只检查字段）")
            chj = c.post("/api/challenge", json={"purpose": "me"}).json()
            check(chj["ttl_seconds"] == 60 and chj["method"] == "GET"
                  and chj["path"] == "/api/me",
                  f"挑战载荷含 TTL=60 与方法路径（实际 {chj}）")

            print("10. 注销：挑战消费与会话删除同一事务")
            r = signed_request(c, key, "/api/logout", "logout", "POST")
            check(r.status_code == 204, f"签名注销 204（实际 {r.status_code}）")
            check(c.get("/api/me").status_code == 401, "注销后 Cookie 立即失效 → 401")
            check(c.post("/api/challenge", json={"purpose": "me"}).status_code == 401,
                  "注销后无法再领挑战 → 401")

            print("11. 复制 Cookie 的无密钥攻击者")
            # 重新登录拿到新会话
            r = c.post("/api/login", json={
                "username": "bob", "password": "bob-pass-2026",
                "public_key": key.public_key_b64})
            check(r.status_code == 200, "bob 重新登录")
            stolen = c.cookies["session"]
            with httpx.Client(base_url=base, timeout=30,
                              cookies={"session": stolen}) as attacker:
                check(attacker.get("/api/me").status_code == 401,
                      "攻击者仅持 Cookie GET → 401")
                ch = attacker.post("/api/challenge", json={"purpose": "me"})
                check(ch.status_code == 200, "攻击者凭有效 Cookie 可领挑战")
                # 没有私钥：随机签名
                rr = attacker.get("/api/me", headers={
                    "X-Auth-Challenge": ch.json()["challenge"],
                    "X-Auth-Signature": b64url(b"\x02" * 64)})
                check(rr.status_code == 401, "无密钥伪造签名 → 401")

            print("12. 不同密钥的签名被拒（换浏览器密钥）")
            other = BrowserKey()
            # 用 other 对当前会话的挑战签名（会话绑的是 key 的公钥）
            ch = c.post("/api/challenge", json={"purpose": "me"}).json()["challenge"]
            r = c.get("/api/me", headers={
                "X-Auth-Challenge": ch,
                "X-Auth-Signature": other.sign(ch, "GET", "/api/me")})
            check(r.status_code == 401, "非绑定密钥签名 → 401")

            print("13. 重启后会话与未过期挑战保留")
            # 先领一个挑战
            ch_before = c.post("/api/challenge",
                               json={"purpose": "me"}).json()["challenge"]
            stopped = stop_server(server)
            if not stopped:
                # Sandbox denies signals: stand up a second process on a new
                # port against the SAME database file -- equivalent to the
                # two-process shared-SQLite docker topology.
                port = port + 100
                server = start_server(port)
                live_servers.append(server)
            else:
                server = start_server(port)
                live_servers.append(server)
            base = f"http://127.0.0.1:{port}"
            # Preserve the session cookie across the new base URL.
            c = httpx.Client(base_url=base, timeout=30,
                             cookies={"session": c.cookies["session"]})
            r = c.get("/api/me", headers={
                "X-Auth-Challenge": ch_before,
                "X-Auth-Signature": key.sign(ch_before, "GET", "/api/me")})
            check(r.status_code == 200, f"重启前领的未过期挑战在重启后仍可用（实际 {r.status_code} {r.text}）")
            check(signed_request(c, key, "/api/me", "me", "GET").status_code == 200,
                  "重启后会话保留且可签名访问")

            print("14. 旧版未绑定会话拒绝")
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute(
                "INSERT INTO sessions (token, account_id, created_at, expires_at,"
                " public_key, bound) VALUES ('legacy-token', 1, ?, ?, '', 0)",
                (time.time(), time.time() + 600))
            conn.commit()
            conn.close()
            with httpx.Client(base_url=base, timeout=30,
                              cookies={"session": "legacy-token"}) as legacy:
                check(legacy.get("/api/me").status_code == 401,
                      "未绑定公钥的旧会话 GET → 401")
                check(legacy.post("/api/challenge",
                                  json={"purpose": "me"}).status_code == 401,
                      "未绑定旧会话不能领挑战 → 401")

            print("15. 非法公钥不消耗登录名额")
            before = httpx.get(f"{base}/api/stats").json()
            r = httpx.post(f"{base}/api/login", json={
                "username": "alice", "password": "whatever",
                "public_key": "not-a-key!!!"})
            check(r.status_code == 400, f"非法公钥 → 400（实际 {r.status_code}）")
            after = httpx.get(f"{base}/api/stats").json()
            check(before["accounts"] == after["accounts"],
                  "非法公钥请求未改变名额状态")

    finally:
        for proc in live_servers:
            stop_server(proc)

    print()
    if failures:
        print(f"{len(failures)} 项失败：")
        for f in failures:
            print(" -", f)
        return 1
    print("全部冒烟检查通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
