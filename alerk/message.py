# coding: utf-8

from pydantic import BaseModel
from typing import List, Self
import json
import os
import base64
import random
import hashlib
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from alerk.crypto import asym_encrypt, asym_decrypt, gen_asym_keys


class MessageEn(BaseModel):
    h: str
    m: List[str]  # max len 214


class MessageContainer:

    SALT_SIZE: int = 16
    CHUNK_BEFORE_SALT_MIN_SIZE: int = 50
    CHUNK_BEFORE_SALT_MAX_SIZE: int = 170 # 16 + 170 + 16 < 214

    def __init__(self, data: dict[str: str] | MessageEn):
        if isinstance(data, MessageEn):
            self._type = True
        elif isinstance(data, dict):
            self._type = False
        else:
            raise ValueError("data must be only dict[str: str] or tuple[MessageCoded, RSAPrivateKey]")
        self.data = data

    def get_data(self):
        return self.data

    def encrypt(self, pub_key: RSAPublicKey) -> Self:
        if self.is_contains_decrypted():
            msgen = MessageContainer._to_en(self.data, pub_key)
            return MessageContainer(msgen)
        else:
            raise ValueError("This container contains already encrypted data.")

    def decrypt(self, priv_key: RSAPrivateKey):
        if self.is_contains_encrypted():
            msgde = MessageContainer._to_de(self.data, priv_key)
            return MessageContainer(msgde)
        else:
            raise ValueError("This container contains already decrypted data.")


    def is_contains_decrypted(self):
        return self._type == False


    def is_contains_encrypted(self):
        return self._type == True


    @staticmethod
    def _to_en(d: dict[str: str], pub_key: RSAPublicKey) -> MessageEn:
        d_str = json.dumps(d)
        byte_array = d_str.encode(encoding="utf-8")
        chunks = MessageContainer.split_byte_array(byte_array)
        res: list[str] = []
        for chunk_i in chunks:
            salt1 = os.urandom(MessageContainer.SALT_SIZE)
            salt2 = os.urandom(MessageContainer.SALT_SIZE)
            bs = salt1 + chunk_i + salt2
            bs = asym_encrypt(bs, pub_key)
            buff = base64.b64encode(bs).decode(encoding="utf-8")
            res.append(buff)  # max len 214

        hash_object = hashlib.sha256()
        for bs_i in res:
            hash_object.update(bs_i.encode(encoding="utf-8"))
        salt = os.urandom(MessageContainer.SALT_SIZE)
        h_b = salt + hash_object.digest()
        h_b_en = asym_encrypt(h_b, pub_key)
        h = base64.b64encode(h_b_en).decode(encoding="utf-8")

        mc = MessageEn(h=h, m=res)
        return mc

    @staticmethod
    def _to_de(men: MessageEn, priv_key: RSAPrivateKey) -> dict[str: str]:
        h_b_en = base64.b64decode(men.h)
        h_b = asym_decrypt(h_b_en, priv_key)
        h_b = h_b[MessageContainer.SALT_SIZE:]

        hash_object = hashlib.sha256()
        for bs_i in men.m:
            hash_object.update(bs_i.encode(encoding="utf-8"))

        if h_b != hash_object.digest():
            raise ValueError(f"Wrong key or data")

        byte_list = []
        for el_i in men.m:
            bs = base64.b64decode(el_i)
            decoded_bytes = asym_decrypt(bs, priv_key)
            decoded_bytes = decoded_bytes[MessageContainer.SALT_SIZE:-MessageContainer.SALT_SIZE]
            byte_list.append(decoded_bytes)
        res = b''.join(byte_list)
        d_str = res.decode(encoding="utf-8")
        d = json.loads(d_str)
        return d

    @staticmethod
    def split_byte_array(byte_array):
        min_length, max_length = MessageContainer.CHUNK_BEFORE_SALT_MIN_SIZE, MessageContainer.CHUNK_BEFORE_SALT_MAX_SIZE
        chunks = []
        i = 0
        while i < len(byte_array):
            chunk_length = random.randint(min_length, max_length)
            chunk = byte_array[i:i + chunk_length]
            chunks.append(chunk)
            i += len(chunk)
        return chunks
