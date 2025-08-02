# coding: utf-8

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from alerk_pack.crypto import str_to_asym_key, calc_key_hash


class Smalk:

    def __init__(self, code: str, pub_key: RSAPublicKey | str, verify_key: RSAPublicKey | str):
        self.code: str = code

        if isinstance(pub_key, RSAPublicKey):
            self.pub_key: RSAPublicKey = pub_key
        elif isinstance(pub_key, str):
            self.pub_key: RSAPublicKey = str_to_asym_key(pub_key, True)
        else:
            raise ValueError("pub_key must be only RSAPublicKey or str")

        self.pub_key_hash: str = calc_key_hash(self.pub_key)

        if isinstance(verify_key, RSAPublicKey):
            self.verify_key: RSAPublicKey = verify_key
        elif isinstance(verify_key, str):
            self.verify_key: RSAPublicKey = str_to_asym_key(verify_key, True)
        else:
            raise ValueError("verify_key must be only RSAPublicKey or str")

        self.verify_key_hash: str = calc_key_hash(self.verify_key)

    def get_code(self) -> str:
        return self.code

    def get_pub_key(self) -> RSAPublicKey:
        return self.pub_key

    def get_verify_key(self) -> RSAPublicKey:
        return self.verify_key

    def get_pub_key_hash(self) -> str:
        return self.pub_key_hash

    def get_verify_key_hash(self) -> str:
        return self.verify_key_hash
