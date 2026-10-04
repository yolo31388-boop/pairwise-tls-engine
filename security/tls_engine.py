"""
游戏内TLS/SSL加密与证书系统 - 核心模块

功能:
- handshake()           : 完整握手（临时 Diffie-Hellman 密钥交换 + 对端证书验证）
- certificate_verify()  : 证书链校验（签发者链 + 有效期）
- encrypt()/decrypt()   : 对称加密（SHA-256 CTR 流密码）+ HMAC-SHA256 消息认证
- key_exchange()        : 有限域 Diffie-Hellman，每次会话使用临时密钥（前向保密）
- session_resume()      : 加密认证的会话票证，带超时过期

仅使用 Python 标准库，不引入第三方依赖。
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import hashlib
import hmac
import json
import math
import secrets
import time


# RFC 3526 - 2048-bit MODP Group 14，Diffie-Hellman 公共参数
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
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
_DH_G = 2

_DEFAULT_SESSION_TIMEOUT = 3600.0
_DEFAULT_CERT_VALIDITY = 86400.0 * 365
_RSA_BITS = 1024
_RSA_E = 65537


class TLSError(Exception):
    """TLS 引擎错误基类。"""


class HandshakeError(TLSError):
    """握手失败（密钥交换或证书验证未通过）。"""


class CertificateError(TLSError):
    """证书无效。"""


class DecryptionError(TLSError):
    """解密失败或消息认证码不匹配。"""


class KeyExchangeError(TLSError):
    """Diffie-Hellman 密钥交换失败。"""


class SessionError(TLSError):
    """会话恢复失败（票证无效、被篡改或已过期）。"""


@dataclass
class Config:
    pass


# ---------------------------------------------------------------------------
# 底层原语：素数 / RSA（用于证书签名）
# ---------------------------------------------------------------------------

def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
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


def generate_rsa_keypair(bits: int = _RSA_BITS) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """返回 ((e, n) 公钥, (d, n) 私钥)。"""
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(_RSA_E, phi) == 1:
            d = pow(_RSA_E, -1, phi)
            return (_RSA_E, n), (d, n)


def _rsa_sign(private_key: Tuple[int, int], payload: bytes) -> int:
    d, n = private_key
    digest = int.from_bytes(hashlib.sha256(payload).digest(), "big")
    return pow(digest, d, n)


def _rsa_verify(public_key: Tuple[int, int], signature: int, payload: bytes) -> bool:
    e, n = public_key
    if not isinstance(signature, int) or signature <= 0 or signature >= n:
        return False
    digest = int.from_bytes(hashlib.sha256(payload).digest(), "big")
    return pow(signature, e, n) == digest


# ---------------------------------------------------------------------------
# 对称加密：SHA-256 计数器流密码 + HMAC-SHA256 消息认证
# ---------------------------------------------------------------------------

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def _symmetric_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    return _xor(plaintext, _keystream(key, nonce, len(plaintext)))


def _mac(mac_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# 证书与证书机构
# ---------------------------------------------------------------------------

@dataclass
class Certificate:
    subject: str
    issuer: str
    public_key: Tuple[int, int]
    not_before: float
    not_after: float
    serial: int = field(default_factory=lambda: secrets.randbits(64))
    signature: int = 0

    def payload(self) -> bytes:
        body = {
            "subject": self.subject,
            "issuer": self.issuer,
            "public_key": list(self.public_key),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial": self.serial,
        }
        return json.dumps(body, sort_keys=True).encode("utf-8")


class CertificateAuthority:
    def __init__(self,
                 subject: str,
                 issuer: "Optional[CertificateAuthority]" = None,
                 validity_seconds: float = _DEFAULT_CERT_VALIDITY,
                 now: Optional[float] = None):
        current = time.time() if now is None else now
        self.subject = subject
        self.public_key, self._private_key = generate_rsa_keypair()
        if issuer is None:
            cert = Certificate(subject, subject, self.public_key,
                               current, current + validity_seconds)
            cert.signature = _rsa_sign(self._private_key, cert.payload())
        else:
            cert = issuer.sign(subject, self.public_key,
                               not_before=current,
                               not_after=current + validity_seconds)
        self.certificate = cert

    def sign(self,
             subject: str,
             public_key: Tuple[int, int],
             not_before: Optional[float] = None,
             not_after: Optional[float] = None,
             now: Optional[float] = None) -> Certificate:
        current = time.time() if now is None else now
        start = current if not_before is None else not_before
        end = current + _DEFAULT_CERT_VALIDITY if not_after is None else not_after
        cert = Certificate(subject, self.subject, public_key, start, end)
        cert.signature = _rsa_sign(self._private_key, cert.payload())
        return cert


# ---------------------------------------------------------------------------
# TLS 引擎
# ---------------------------------------------------------------------------

class TLSEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._state = {}
        self._history = []
        self.session_timeout = float(
            self.config.get("session_timeout", _DEFAULT_SESSION_TIMEOUT))
        self._trusted_roots: Dict[str, Certificate] = {}
        self._sessions: Dict[str, Dict] = {}
        self._ticket_key = secrets.token_bytes(32)
        for root in self.config.get("trusted_roots", []) or []:
            self.add_trusted_root(root)

    def update(self, dt: float):
        pass

    def reset(self):
        self._state = {}
        self._history = []
        self._sessions = {}

    # -- 信任锚 ---------------------------------------------------------

    def add_trusted_root(self, cert: Certificate):
        self._trusted_roots[cert.subject] = cert

    # -- 密钥交换（Diffie-Hellman，临时密钥 => 前向保密） -----------------

    def generate_dh_keypair(self) -> Tuple[int, int]:
        private = secrets.randbelow(_DH_P - 3) + 2
        public = pow(_DH_G, private, _DH_P)
        return private, public

    def key_exchange(self, peer_public: int, private: Optional[int] = None) -> bytes:
        if not isinstance(peer_public, int) or not (2 <= peer_public <= _DH_P - 2):
            raise KeyExchangeError("对端 DH 公钥非法（可能是小群/公钥替换攻击）")
        own_private = private if private is not None else self.generate_dh_keypair()[0]
        shared = pow(peer_public, own_private, _DH_P)
        if shared <= 1:
            raise KeyExchangeError("协商出的共享密钥非法")
        return hashlib.sha256(shared.to_bytes(256, "big")).digest()

    # -- 证书验证：签发者链 + 有效期 -------------------------------------

    def certificate_verify(self,
                           chain: List[Certificate],
                           now: Optional[float] = None) -> bool:
        if not chain:
            return False
        current = time.time() if now is None else now
        for index, cert in enumerate(chain):
            if not isinstance(cert, Certificate):
                return False
            if cert.not_before > current:
                return False
            if cert.not_after < current:
                return False
            if index + 1 < len(chain):
                issuer_cert = chain[index + 1]
            else:
                issuer_cert = self._trusted_roots.get(cert.issuer)
            if issuer_cert is None or issuer_cert.subject != cert.issuer:
                return False
            if not _rsa_verify(issuer_cert.public_key, cert.signature, cert.payload()):
                return False
        top = chain[-1]
        return top.issuer in self._trusted_roots

    # -- 握手：密钥交换 + 证书验证 + 密钥派生 -----------------------------

    @staticmethod
    def _derive_key(shared_secret: bytes, label: bytes) -> bytes:
        return hmac.new(shared_secret, label, hashlib.sha256).digest()

    def handshake(self,
                  peer: "TLSEngine",
                  cert_chain: Optional[List[Certificate]] = None,
                  require_peer_cert: bool = True) -> Dict:
        if not isinstance(peer, TLSEngine):
            raise HandshakeError("对端不是 TLSEngine")
        if cert_chain:
            if not self.certificate_verify(cert_chain):
                raise HandshakeError("对端证书验证失败：证书链或有效期不合法")
        elif require_peer_cert:
            raise HandshakeError("缺少对端证书，无法完成握手")

        client_private, client_public = self.generate_dh_keypair()
        server_private, server_public = peer.generate_dh_keypair()
        try:
            client_secret = self.key_exchange(server_public, client_private)
            server_secret = peer.key_exchange(client_public, server_private)
        except KeyExchangeError as exc:
            raise HandshakeError(str(exc)) from exc
        if not hmac.compare_digest(client_secret, server_secret):
            raise HandshakeError("双方协商密钥不一致")

        session_id = secrets.token_hex(16)
        session = {
            "id": session_id,
            "state": "established",
            "key_exchange": "DHE",
            "cipher": "SHA256-STREAM+HMAC-SHA256",
            "enc_key": self._derive_key(client_secret, b"game-tls-enc"),
            "mac_key": self._derive_key(client_secret, b"game-tls-mac"),
            "client_public": client_public,
            "server_public": server_public,
            "created_at": time.time(),
        }
        self._sessions[session_id] = session
        peer._sessions[session_id] = session
        self._history.append(("handshake", session_id))
        peer._history.append(("handshake", session_id))
        return session

    # -- 应用数据：对称加密 + 消息认证（先加密后认证） -------------------

    def _require_session(self, session_id: str) -> Dict:
        session = self._sessions.get(session_id)
        if session is None:
            raise TLSError("会话不存在，需要先握手或恢复会话")
        return session

    @staticmethod
    def _as_bytes(value) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return bytes.fromhex(value)
        raise TLSError("数据必须是 bytes 或 hex 字符串")

    def encrypt(self, session_id: str, plaintext) -> Dict:
        session = self._require_session(session_id)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = secrets.token_bytes(16)
        ciphertext = _symmetric_encrypt(session["enc_key"], nonce, plaintext)
        tag = _mac(session["mac_key"], nonce, ciphertext)
        return {"nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex()}

    def decrypt(self, session_id: str, ciphertext, nonce=None, tag=None) -> bytes:
        session = self._require_session(session_id)
        if isinstance(ciphertext, dict):
            nonce = ciphertext["nonce"]
            tag = ciphertext["tag"]
            ciphertext = ciphertext["ciphertext"]
        nonce_bytes = self._as_bytes(nonce)
        tag_bytes = self._as_bytes(tag)
        ct_bytes = self._as_bytes(ciphertext)
        expected = _mac(session["mac_key"], nonce_bytes, ct_bytes)
        if not hmac.compare_digest(expected, tag_bytes):
            raise DecryptionError("消息认证失败：数据可能已被篡改或密钥不匹配")
        return _symmetric_encrypt(session["enc_key"], nonce_bytes, ct_bytes)

    # -- 会话恢复：加密认证的会话票证 + 超时过期 -------------------------

    def _seal_ticket(self, payload: Dict) -> str:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        nonce = secrets.token_bytes(16)
        ciphertext = _symmetric_encrypt(self._ticket_key, nonce, data)
        tag = _mac(self._ticket_key, nonce, ciphertext)
        return (nonce + tag + ciphertext).hex()

    def _unseal_ticket(self, token: str) -> Dict:
        try:
            raw = bytes.fromhex(token)
        except (ValueError, TypeError) as exc:
            raise SessionError("会话票证格式非法") from exc
        if len(raw) < 48:
            raise SessionError("会话票证格式非法")
        nonce, tag, ciphertext = raw[:16], raw[16:48], raw[48:]
        expected = _mac(self._ticket_key, nonce, ciphertext)
        if not hmac.compare_digest(expected, tag):
            raise SessionError("会话票证认证失败（票证被篡改或伪造）")
        data = _symmetric_encrypt(self._ticket_key, nonce, ciphertext)
        try:
            return json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SessionError("会话票证内容无法解析") from exc

    def issue_session_ticket(self, session_id: str, now: Optional[float] = None) -> Dict:
        session = self._require_session(session_id)
        current = time.time() if now is None else now
        expires_at = current + self.session_timeout
        payload = {
            "session_id": session_id,
            "enc_key": session["enc_key"].hex(),
            "mac_key": session["mac_key"].hex(),
            "issued_at": current,
            "expires_at": expires_at,
        }
        return {"ticket": self._seal_ticket(payload), "expires_at": expires_at}

    def session_resume(self, ticket, now: Optional[float] = None) -> Dict:
        token = ticket["ticket"] if isinstance(ticket, dict) else ticket
        payload = self._unseal_ticket(token)
        current = time.time() if now is None else now
        if current > float(payload["expires_at"]):
            raise SessionError("会话票证已过期，需要重新完整握手")
        session = {
            "id": payload["session_id"],
            "state": "resumed",
            "key_exchange": "DHE",
            "cipher": "SHA256-STREAM+HMAC-SHA256",
            "enc_key": bytes.fromhex(payload["enc_key"]),
            "mac_key": bytes.fromhex(payload["mac_key"]),
            "created_at": float(payload["issued_at"]),
            "resumed_at": current,
        }
        self._sessions[session["id"]] = session
        self._history.append(("session_resume", session["id"]))
        return session
