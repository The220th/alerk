# coding: utf-8

from ksupk import singleton_decorator
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from alerk.crypto import calc_key_hash, str_to_asym_key
from alerk.setting_manager import SettingManager
from alerk.smalk import Smalk


@singleton_decorator
class KeyManager:

    def __init__(self, sm: SettingManager):
        self.__priv_key: RSAPrivateKey = str_to_asym_key(sm.get_priv_key(), False)
        self.__pub_key: RSAPublicKey = str_to_asym_key(sm.get_pub_key(), True)
        self.__sign_key: RSAPrivateKey = str_to_asym_key(sm.get_sign_key(), False)
        self.__verify_key: RSAPublicKey = str_to_asym_key(sm.get_verify_key(), True)

        self.__smalks: list[Smalk] = sm.get_smalks()
        self.__smalks_hash_d: dict[str: Smalk] = {smalk_i.get_pub_key_hash(): smalk_i for smalk_i in self.__smalks}
        self.__smalks_hash_d.update({smalk_i.get_verify_key_hash(): smalk_i for smalk_i in self.__smalks})

    def get_priv_key(self) -> RSAPrivateKey:
        return self.__priv_key

    def get_pub_key(self) -> RSAPublicKey:
        return self.__pub_key

    def get_sign_key(self) -> RSAPrivateKey:
        return self.__sign_key

    def get_verify_key(self) -> RSAPublicKey:
        return self.__verify_key

    def get_smalk_by_hash(self, hash_str: str) -> Smalk | None:
        return self.__smalks_hash_d.get(hash_str, None)
