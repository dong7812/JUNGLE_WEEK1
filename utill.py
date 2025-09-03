import os, base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def encrypt(plaintext: str, passphrase: str, *, aad: Optional[bytes] = None) -> str:
    """
    AES-256-GCM으로 암호화하고, salt|nonce|ciphertext 를 하나로 붙여 Base64로 반환.
    - plaintext: 평문 문자열 (UTF-8)
    - passphrase: 사용자가 기억/보관하는 비밀 문자열
    - aad: (선택) 추가 인증 데이터. 복호화 시 동일 값 필요
    반환: url-safe Base64 문자열
    """
    # 키 파생용 솔트 & Nonce(IV)
    salt = os.urandom(16)     # PBKDF2 salt
    nonce = os.urandom(12)    # GCM 표준 12바이트

    # PBKDF2-HMAC(SHA256)으로 32바이트 키 파생 → AES-256
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    key = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)  # ct = ciphertext || tag

    # 간단한 버전 바이트(0x01) + salt + nonce + ct 를 Base64로
    token = b"\x01" + salt + nonce + ct
    return base64.urlsafe_b64encode(token).decode("ascii")


def decrypt(token_b64: str, passphrase: str, *, aad: Optional[bytes] = None) -> str:
    """
    encrypt_text로 만든 Base64 토큰을 복호화해 UTF-8 문자열로 반환.
    - token_b64: encrypt_text 결과(Base64)
    - passphrase: 암호화 때 사용한 동일한 비밀 문자열
    - aad: (선택) 암호화 시 넣었던 AAD가 있었다면 동일 값 필요
    """
    raw = base64.urlsafe_b64decode(token_b64.encode("ascii"))
    if len(raw) < 1 + 16 + 12 + 16:
        raise ValueError("invalid token")

    ver = raw[0]
    if ver != 0x01:
        raise ValueError("unsupported token version")

    salt = raw[1:17]
    nonce = raw[17:29]
    ct = raw[29:]

    # 동일한 방식으로 키 재생성
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    key = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")
