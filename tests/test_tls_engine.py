"""
游戏内TLS/SSL加密与证书系统 - 验收测试
运行方式：python -m pytest tests/test_tls_engine.py -q
共 16 个测试用例
"""
import codecs
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security import tls_engine
from security.tls_engine import (
    TLSEngine,
    create_certificate,
    generate_rsa_keypair,
)

# 整模块共享一对 CA / 服务器 RSA 密钥（密钥生成较慢，避免每个用例重复生成）
ROOT_KEY = generate_rsa_keypair()
ROOT_PUBLIC = (ROOT_KEY["n"], ROOT_KEY["e"])
SERVER_KEY = generate_rsa_keypair()
SERVER_PUBLIC = (SERVER_KEY["n"], SERVER_KEY["e"])
EVIL_KEY = generate_rsa_keypair()


def make_chain(engine, leaf=None, root=None, now=None,
               offset_before=-100, offset_after=86400):
    now = time.time() if now is None else now
    if leaf is None:
        leaf = create_certificate(
            "game-server", SERVER_PUBLIC, "RootCA", ROOT_KEY,
            now + offset_before, now + offset_after)
    chain = [leaf]
    if root is not None:
        chain.append(root)
    return chain


class TestTLSEngine:
    def setup_method(self):
        self.system = TLSEngine()
        self.system.add_trusted_root("RootCA", ROOT_PUBLIC)
        self.now = time.time()
        self.server_cert = create_certificate(
            "game-server", SERVER_PUBLIC, "RootCA", ROOT_KEY,
            self.now - 100, self.now + 86400)
        self.root_cert = create_certificate(
            "RootCA", ROOT_PUBLIC, "RootCA", ROOT_KEY,
            self.now - 3600, self.now + 864000)
        self.chain = [self.server_cert]

    # -- 握手 --------------------------------------------------------------

    def test_case_01(self):
        """握手能够建立安全连接，派生出会话密钥"""
        session, local_public = self.system.handshake(self.chain)
        assert session is not None
        assert local_public is not None
        assert self.system._state.get("established") is True
        assert len(session.enc_key) == 32
        assert len(session.mac_key) == 32
        assert ("handshake", session.session_id) in self.system._history

    def test_case_02(self):
        """握手包含密钥交换：协商出独立于传输公钥的会话密钥"""
        session, local_public = self.system.handshake(self.chain)
        assert isinstance(local_public, int)
        assert 2 <= local_public <= tls_engine._DH_P - 2
        assert session.enc_key != session.mac_key
        # 会话主密钥绝不能等于/暴露在线缆上传输的任何 DH 公钥
        leaked = (local_public.to_bytes(256, "big"),
                  session.enc_key[:256])
        assert session.master_key not in leaked
        assert local_public != tls_engine._DH_G

    def test_case_03(self):
        """握手会验证证书，不可信证书链直接拒绝建立连接"""
        evil_cert = create_certificate(
            "game-server", SERVER_PUBLIC, "EvilCA", EVIL_KEY,
            self.now - 100, self.now + 86400)
        session, local_public = self.system.handshake([evil_cert])
        assert session is None
        assert local_public is None
        assert self.system._state.get("established") is False

    # -- 证书验证 ----------------------------------------------------------

    def test_case_04(self):
        """合法证书链（含完整到根CA的链）验证通过"""
        assert self.system.certificate_verify([self.server_cert]) is True
        assert self.system.certificate_verify(
            [self.server_cert, self.root_cert]) is True

    def test_case_05(self):
        """验证证书链：未受信签发者 / 链中签发者不匹配均失败"""
        evil_cert = create_certificate(
            "game-server", SERVER_PUBLIC, "EvilCA", EVIL_KEY,
            self.now - 100, self.now + 86400)
        assert self.system.certificate_verify([evil_cert]) is False
        other_ca_cert = create_certificate(
            "RootCA", ROOT_PUBLIC, "RootCA", ROOT_KEY,
            self.now - 3600, self.now + 864000)
        other_ca_cert["subject"] = "OtherCA"  # subject 与 leaf.issuer 不一致
        assert self.system.certificate_verify(
            [self.server_cert, other_ca_cert]) is False

    def test_case_06(self):
        """过期证书验证失败"""
        expired = create_certificate(
            "game-server", SERVER_PUBLIC, "RootCA", ROOT_KEY,
            self.now - 86400, self.now - 1)
        assert self.system.certificate_verify([expired]) is False

    def test_case_07(self):
        """尚未生效（not_before 在未来）的证书验证失败"""
        future = create_certificate(
            "game-server", SERVER_PUBLIC, "RootCA", ROOT_KEY,
            self.now + 3600, self.now + 86400)
        assert self.system.certificate_verify([future]) is False

    def test_case_08(self):
        """证书内容被篡改后签名校验失败，任意证书不能通过"""
        tampered = dict(self.server_cert)
        tampered["subject"] = "attacker.example"
        assert self.system.certificate_verify([tampered]) is False

    # -- 加密 --------------------------------------------------------------

    def test_case_09(self):
        """对称加密后不是明文，也不是 ROT13 之类的伪加密"""
        session, _ = self.system.handshake(self.chain)
        plaintext = b"user=player1;password=secret"
        packet = self.system.encrypt(session, plaintext)
        assert packet["ciphertext"] != plaintext
        rot13 = codecs.encode(plaintext.decode(), "rot13").encode()
        assert packet["ciphertext"] != rot13
        assert packet["tag"]

    def test_case_10(self):
        """密文可正确解密还原（含中文/二进制负载）"""
        session, _ = self.system.handshake(self.chain)
        for plaintext in (b"", b"a", b"\x00\x01\x02\xff" * 8, "密码登录请求".encode()):
            packet = self.system.encrypt(session, plaintext)
            assert self.system.decrypt(session, packet) == plaintext

    def test_case_11(self):
        """消息认证：密文或认证码被篡改时解密被拒绝"""
        session, _ = self.system.handshake(self.chain)
        plaintext = b"transfer=1000;to=alice"
        packet = self.system.encrypt(session, plaintext)

        tampered_body = dict(packet)
        tampered_body["ciphertext"] = bytes(
            [packet["ciphertext"][0] ^ 0x01]) + packet["ciphertext"][1:]
        with pytest.raises(ValueError):
            self.system.decrypt(session, tampered_body)

        tampered_tag = dict(packet)
        tampered_tag["tag"] = bytes([packet["tag"][0] ^ 0xFF]) + packet["tag"][1:]
        with pytest.raises(ValueError):
            self.system.decrypt(session, tampered_tag)

    # -- 密钥交换 ----------------------------------------------------------

    def test_case_12(self):
        """Diffie-Hellman：双方各自协商出相同的共享密钥"""
        peer = TLSEngine()
        exchange_a = self.system.key_exchange()
        exchange_b = peer.key_exchange()
        secret_a = self.system.compute_shared_secret(
            exchange_a, exchange_b["public"])
        secret_b = peer.compute_shared_secret(
            exchange_b, exchange_a["public"])
        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_case_13(self):
        """DH 临时密钥对每次不同，私钥不以明文在网络中传输"""
        ex1 = self.system.key_exchange()
        ex2 = self.system.key_exchange()
        assert ex1["private"] != ex2["private"]
        assert ex1["public"] != ex2["public"]
        assert pow(tls_engine._DH_G, ex1["private"],
                   tls_engine._DH_P) == ex1["public"]
        secret = self.system.compute_shared_secret(ex1, ex2["public"])
        # 网络上只传公钥；共享密钥与公钥不同，且无法从公钥直接得到
        assert secret != ex1["public"].to_bytes(256, "big")
        assert secret != ex2["public"].to_bytes(256, "big")

    def test_case_14(self):
        """前向保密：每次握手使用新临时密钥，长期密钥泄露无法解密历史会话"""
        session1, public1 = self.system.handshake(self.chain)
        session2, public2 = self.system.handshake(self.chain)
        assert public1 != public2
        assert session1.master_key != session2.master_key
        assert session1.enc_key != session2.enc_key
        # 会话中不保留任何 DH 临时私钥
        assert not any("private" in key for key in vars(session1))

    # -- 会话恢复 ----------------------------------------------------------

    def test_case_15(self):
        """会话票证恢复：无需完整握手即可恢复会话"""
        ticket_key = os.urandom(32)
        server = TLSEngine({"ticket_key": ticket_key})
        server.add_trusted_root("RootCA", ROOT_PUBLIC)
        session, _ = server.handshake(self.chain)
        ticket = server.issue_session_ticket(session)

        # 服务端新连接（同一票证密钥），凭票证直接恢复，无需完整握手
        client = TLSEngine({"ticket_key": ticket_key})
        resumed = client.session_resume(ticket)
        assert resumed is not None
        assert resumed.resumed is True
        assert resumed.session_id == session.session_id
        assert resumed.master_key == session.master_key
        assert ("resumed", session.session_id) in client._history
        # 恢复后使用同一组密钥仍能正常加解密
        packet = server.encrypt(session, b"resume-ok")
        assert client.decrypt(resumed, packet) == b"resume-ok"

    def test_case_16(self):
        """会话票证有超时控制，过期票证与篡改票证都不能恢复"""
        session, _ = self.system.handshake(self.chain)
        ticket = self.system.issue_session_ticket(session)

        client = TLSEngine()
        client.update(client.ticket_timeout + 1)  # 时钟推进，票证过期
        assert client.session_resume(ticket) is None

        fresh_client = TLSEngine()
        fake_ticket = bytes([ticket[0] ^ 0x01]) + ticket[1:]
        assert fresh_client.session_resume(fake_ticket) is None
        assert fresh_client._state.get("established") is not True


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
