"""
游戏内TLS/SSL加密与证书系统 - 核心模块

安全特性：
- 握手：临时 Diffie-Hellman 密钥交换 + 证书链验证，失败则拒绝建立连接
- 证书：签发者链式验证（直至受信根CA）+ 有效期检查 + RSA 签名校验
- 加密：HMAC-CTR 对称流加密 + Encrypt-then-MAC 消息认证（防篡改）
- 密钥交换：RFC 3526 2048-bit MODP 群上的临时 DH，提供前向保密
- 会话恢复：加密并签名的会话票证 + 超时控制，过期/篡改票证拒绝恢复

仅使用 Python 标准库。
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import hashlib
import hmac
import json
import os
import secrets
import time


# RFC 3526 2048-bit MODP Group (Group 14)
_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH_G = 2
_DH_BYTES = (_DH_P.bit_length() + 7) // 8

DEFAULT_TICKET_TIMEOUT = 300.0  # 会话票证默认有效期（秒）


# ---------------------------------------------------------------------------
# RSA（用于证书签名/验签，教学级实现）
# ---------------------------------------------------------------------------

def _is_probable_prime(n: int, rounds: int = 20) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 1024) -> Dict:
    """生成 RSA 密钥对 {"n", "e", "d"}，用于 CA / 服务器证书签名。"""
    e = 65537
    while True:
        p = _generate_prime(bits // 2)
        q = _generate_prime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        return {"n": n, "e": e, "d": pow(e, -1, phi)}


def _hash_int(message: bytes) -> int:
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def rsa_sign(private_key: Dict, message: bytes) -> int:
    return pow(_hash_int(message), private_key["d"], private_key["n"])


def rsa_verify(public_key, message: bytes, signature: int) -> bool:
    n, e = int(public_key[0]), int(public_key[1])
    if not (0 <= int(signature) < n):
        return False
    return pow(int(signature), e, n) == _hash_int(message) % n


# ---------------------------------------------------------------------------
# 证书
# ---------------------------------------------------------------------------

def _cert_payload(cert: Dict) -> bytes:
    body = {k: v for k, v in cert.items() if k != "signature"}
    return json.dumps(body, sort_keys=True).encode("utf-8")


def create_certificate(subject: str, subject_public_key, issuer: str,
                       issuer_private_key: Dict, not_before: float,
                       not_after: float) -> Dict:
    """由 issuer 的私钥签发一张证书。"""
    cert = {
        "subject": subject,
        "issuer": issuer,
        "public_key": [int(subject_public_key[0]), int(subject_public_key[1])],
        "not_before": int(not_before),
        "not_after": int(not_after),
    }
    cert["signature"] = rsa_sign(issuer_private_key, _cert_payload(cert))
    return cert


# ---------------------------------------------------------------------------
# 对称加密与消息认证（HMAC-CTR 流加密 + Encrypt-then-MAC）
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"),
                        hashlib.sha256).digest()
        counter += 1
    return out[:length]


def _xor(data: bytes, pad: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, pad))


def _aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    enc_key = _hkdf_expand(key, b"aead-enc", 32)
    mac_key = _hkdf_expand(key, b"aead-mac", 32)
    nonce = os.urandom(16)
    ciphertext = _xor(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    tag = hmac.new(mac_key, aad + nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def _aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    enc_key = _hkdf_expand(key, b"aead-enc", 32)
    mac_key = _hkdf_expand(key, b"aead-mac", 32)
    if len(blob) < 16 + 32:
        raise ValueError("密文长度非法")
    nonce, ciphertext, tag = blob[:16], blob[16:-32], blob[-32:]
    expected = hmac.new(mac_key, aad + nonce + ciphertext,
                        hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("消息认证失败：数据被篡改")
    return _xor(ciphertext, _keystream(enc_key, nonce, len(ciphertext)))


# ---------------------------------------------------------------------------
# 会话
# ---------------------------------------------------------------------------

@dataclass
class Session:
    """握手/恢复后建立的安全会话。不保存任何 DH 私钥（前向保密）。"""
    session_id: str
    master_key: bytes
    enc_key: bytes
    mac_key: bytes
    peer_subject: str = ""
    created_at: float = 0.0
    resumed: bool = False


@dataclass
class Config:
    pass


class TLSEngine:
    """游戏内 TLS/SSL 引擎：握手、证书验证、加密、密钥交换、会话恢复。"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._state = {}
        self._history = []
        self.trusted_roots = dict(self.config.get("trusted_roots", {}))
        self.ticket_timeout = float(
            self.config.get("ticket_timeout", DEFAULT_TICKET_TIMEOUT))
        self._ticket_key = self.config.get("ticket_key") or os.urandom(32)
        self._clock_offset = 0.0

    # -- 游戏循环接口 ------------------------------------------------------

    def update(self, dt: float):
        """推进内部时钟（用于会话票证超时等时间相关逻辑）。"""
        self._clock_offset += float(dt)

    def reset(self):
        self._state = {}
        self._history = []
        self._clock_offset = 0.0

    def _now(self) -> float:
        return time.time() + self._clock_offset

    # -- 信任锚 ------------------------------------------------------------

    def add_trusted_root(self, name: str, public_key):
        self.trusted_roots[name] = (int(public_key[0]), int(public_key[1]))

    # -- 证书验证 ----------------------------------------------------------

    def certificate_verify(self, chain: List[Dict],
                           now: Optional[float] = None) -> bool:
        """
        验证证书链：每级证书由下一级签发，链顶由受信根 CA 签发；
        同时校验每张证书的有效期与 RSA 签名。
        """
        if not chain:
            return False
        now = self._now() if now is None else now
        for i, cert in enumerate(chain):
            if not (cert["not_before"] <= now <= cert["not_after"]):
                return False
            if i + 1 < len(chain):
                issuer_cert = chain[i + 1]
                if issuer_cert["subject"] != cert["issuer"]:
                    return False
                issuer_key = (int(issuer_cert["public_key"][0]),
                              int(issuer_cert["public_key"][1]))
            else:
                issuer_key = self.trusted_roots.get(cert["issuer"])
                if issuer_key is None:
                    return False
            if not rsa_verify(issuer_key, _cert_payload(cert),
                              cert["signature"]):
                return False
        return True

    # -- 密钥交换（临时 Diffie-Hellman，前向保密） --------------------------

    def key_exchange(self) -> Dict:
        """生成一次性临时 DH 密钥对；私钥用完即弃，提供前向保密。"""
        private = secrets.randbelow(_DH_P - 3) + 2
        public = pow(_DH_G, private, _DH_P)
        return {"private": private, "public": public}

    def compute_shared_secret(self, exchange: Dict, peer_public: int) -> bytes:
        """用本地临时私钥与对端公钥计算共享密钥（经 HKDF 派生）。"""
        peer_public = int(peer_public)
        if not (2 <= peer_public <= _DH_P - 2):
            raise ValueError("非法的 DH 公钥")
        shared = pow(peer_public, int(exchange["private"]), _DH_P)
        return _hkdf_extract(b"tls-engine-dh",
                             shared.to_bytes(_DH_BYTES, "big"))

    # -- 握手 ---------------------------------------------------------------

    def handshake(self, peer_cert_chain: List[Dict],
                  peer_dh_public: Optional[int] = None
                  ) -> Tuple[Optional[Session], Optional[int]]:
        """
        完整握手：证书链验证 -> 临时 DH 密钥交换 -> 派生会话密钥。
        返回 (session, local_dh_public)；验证失败返回 (None, None)。
        """
        if not self.certificate_verify(peer_cert_chain):
            self._state["established"] = False
            self._history.append(("handshake_failed", "certificate"))
            return None, None

        local = self.key_exchange()
        if peer_dh_public is None:
            peer = self.key_exchange()  # 模拟对端（回环场景）
            peer_dh_public = peer["public"]
        master_key = self.compute_shared_secret(local, peer_dh_public)
        # 临时私钥随局部变量销毁，不落入会话状态 —— 前向保密
        key_block = _hkdf_expand(_hkdf_extract(b"tls-engine", master_key),
                                 b"session keys", 64)
        session = Session(
            session_id=secrets.token_hex(8),
            master_key=master_key,
            enc_key=key_block[:32],
            mac_key=key_block[32:],
            peer_subject=peer_cert_chain[0].get("subject", ""),
            created_at=self._now(),
        )
        self._state["session"] = session
        self._state["established"] = True
        self._history.append(("handshake", session.session_id))
        return session, local["public"]

    # -- 加密（对称加密 + 消息认证） ----------------------------------------

    def encrypt(self, session: Session, plaintext: bytes) -> Dict:
        """对称加密并附加 HMAC 消息认证码（Encrypt-then-MAC）。"""
        nonce = os.urandom(16)
        ciphertext = _xor(plaintext,
                          _keystream(session.enc_key, nonce, len(plaintext)))
        tag = hmac.new(session.mac_key, nonce + ciphertext,
                       hashlib.sha256).digest()
        return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}

    def decrypt(self, session: Session, packet: Dict) -> bytes:
        """先验证消息认证码，再解密；任何篡改都会抛出 ValueError。"""
        expected = hmac.new(session.mac_key,
                            packet["nonce"] + packet["ciphertext"],
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, packet["tag"]):
            raise ValueError("消息认证失败：数据被篡改")
        return _xor(packet["ciphertext"],
                    _keystream(session.enc_key, packet["nonce"],
                               len(packet["ciphertext"])))

    # -- 会话恢复（会话票证 + 超时） ----------------------------------------

    def issue_session_ticket(self, session: Optional[Session] = None) -> bytes:
        """为当前会话签发加密且带认证的会话票证，含过期时间。"""
        session = session or self._state.get("session")
        if session is None:
            raise ValueError("没有可签发票证的会话")
        payload = json.dumps({
            "session_id": session.session_id,
            "master_key": session.master_key.hex(),
            "peer_subject": session.peer_subject,
            "expires_at": self._now() + self.ticket_timeout,
        }).encode("utf-8")
        return _aead_encrypt(self._ticket_key, payload, aad=b"session-ticket")

    def session_resume(self, ticket: bytes) -> Optional[Session]:
        """
        用会话票证恢复会话（无需完整握手）。
        票证被篡改或超过有效期（超时）时拒绝恢复，返回 None。
        """
        try:
            payload = _aead_decrypt(self._ticket_key, bytes(ticket),
                                    aad=b"session-ticket")
            data = json.loads(payload.decode("utf-8"))
        except (ValueError, KeyError, json.JSONDecodeError):
            self._history.append(("resume_failed", "invalid_ticket"))
            return None
        if not isinstance(data.get("expires_at"), (int, float)) \
                or data["expires_at"] < self._now():
            self._history.append(("resume_failed", "expired"))
            return None
        master_key = bytes.fromhex(data["master_key"])
        key_block = _hkdf_expand(_hkdf_extract(b"tls-engine", master_key),
                                 b"session keys", 64)
        session = Session(
            session_id=data["session_id"],
            master_key=master_key,
            enc_key=key_block[:32],
            mac_key=key_block[32:],
            peer_subject=data.get("peer_subject", ""),
            created_at=self._now(),
            resumed=True,
        )
        self._state["session"] = session
        self._state["established"] = True
        self._history.append(("resumed", session.session_id))
        return session
