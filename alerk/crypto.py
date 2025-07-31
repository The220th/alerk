# coding: utf-8

import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization


def gen_asym_keys() -> tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def asym_key_to_str(key: RSAPrivateKey | RSAPublicKey) -> str:
    if isinstance(key, RSAPrivateKey):
        private_key = key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_str: str = private_pem.decode(encoding="utf-8")
    elif isinstance(key, RSAPublicKey):
        public_key = key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_str: str = public_pem.decode(encoding="utf-8")
    else:
        raise ValueError(f"Key must be only RSAPrivateKey or RSAPublicKey.")

    byte_string = key_str.encode("utf-8")
    base64_string = base64.b64encode(byte_string).decode('utf-8')

    return base64_string


def str_to_asym_key(key_str_base_64: str, priv_pub: bool) -> RSAPrivateKey | RSAPublicKey:
    decoded_bytes = base64.b64decode(key_str_base_64)
    key_str = decoded_bytes.decode('utf-8')
    key_str = key_str.strip()

    if priv_pub:
        key: RSAPublicKey = serialization.load_pem_public_key(key_str.encode(encoding="utf-8"))
    else:
        key: RSAPrivateKey = serialization.load_pem_private_key(key_str.encode(encoding="utf-8"), password=None)

    return key

def compare_two_keys(key1: RSAPrivateKey | RSAPublicKey, key2: RSAPrivateKey | RSAPublicKey) -> bool:
    if isinstance(key1, RSAPrivateKey) and isinstance(key2, RSAPrivateKey):
        key1_bytes = key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        key2_bytes = key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return key1_bytes == key2_bytes
    elif isinstance(key1, RSAPublicKey) and isinstance(key2, RSAPublicKey):
        key1_bytes = key1.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        key2_bytes = key2.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return key1_bytes == key2_bytes
    else:
        raise ValueError(f"Keys must be only RSAPrivateKey or RSAPublicKey.")
