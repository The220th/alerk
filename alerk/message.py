# coding: utf-8

from pydantic import BaseModel
from typing import List
import json
import os
import base64
import random

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from alerk.crypto import asym_encrypt, asym_decrypt, gen_asym_keys


class MessageCoded(BaseModel):
    m: List[str]  # max len 214


class Message:

    SALT_SIZE: int = 16
    CHUNK_BEFORE_SALT_MIN_SIZE: int = 50
    CHUNK_BEFORE_SALT_MAX_SIZE: int = 170 # 16 + 170 + 16 < 214

    def __init__(self, data: dict[str: str] | tuple[MessageCoded, RSAPrivateKey]):
        if isinstance(data, tuple) and len(data) == 2 and isinstance(data[0], MessageCoded) and isinstance(data[1], RSAPrivateKey):
            self.d = Message.coded_to_dict(data[0], data[1])
        elif isinstance(data, dict):
            self.d = data
        else:
            raise ValueError("data must be only dict[str: str] or tuple[MessageCoded, RSAPrivateKey]")

    def get_data(self):
        return self.d

    def get_as_codded(self, pub_key: RSAPublicKey) -> MessageCoded:
        return Message.transform_as_coded(self.d, pub_key)

    @staticmethod
    def transform_as_coded(d: dict[str: str], pub_key: RSAPublicKey) -> MessageCoded:
        d_str = json.dumps(d)
        byte_array = d_str.encode(encoding="utf-8")
        chunks = Message.split_byte_array(byte_array)
        res = []
        for chunk_i in chunks:
            salt1 = os.urandom(Message.SALT_SIZE)
            salt2 = os.urandom(Message.SALT_SIZE)
            bs = salt1 + chunk_i + salt2
            bs = asym_encrypt(bs, pub_key)
            buff = base64.b64encode(bs).decode('utf-8')
            res.append(buff)  # max len 214
        mc = MessageCoded(m=res)
        return mc

    @staticmethod
    def coded_to_dict(mc: MessageCoded, priv_key: RSAPrivateKey) -> dict[str: str]:
        byte_list = []
        for el_i in mc.m:
            bs = base64.b64decode(el_i)
            decoded_bytes = asym_decrypt(bs, priv_key)
            decoded_bytes = decoded_bytes[Message.SALT_SIZE:-Message.SALT_SIZE]
            byte_list.append(decoded_bytes)
        res = b''.join(byte_list)
        d_str = res.decode(encoding="utf-8")
        d = json.loads(d_str)
        return d

    @staticmethod
    def split_byte_array(byte_array):
        min_length, max_length = Message.CHUNK_BEFORE_SALT_MIN_SIZE, Message.CHUNK_BEFORE_SALT_MAX_SIZE
        chunks = []
        i = 0
        while i < len(byte_array):
            chunk_length = random.randint(min_length, max_length)
            chunk = byte_array[i:i + chunk_length]
            chunks.append(chunk)
            i += len(chunk)
        return chunks


def test_ejh3jvnnbt():
    from ksupk import gen_random_string
    from tqdm import tqdm
    for i in tqdm(range(1000)):
        priv_key, pub_key = gen_asym_keys()
        records = random.randint(4, 1000)
        d = {}
        for _ in range(records):
            rnd_str = gen_random_string()
            d[rnd_str] = gen_random_string(random.randint(0, 1000))

        msg = Message(d)
        mc = msg.get_as_codded(pub_key)
        msg2 = Message((mc, priv_key))
        assert msg.get_data() == msg2.get_data()

if __name__ == "__main__":
    test_ejh3jvnnbt()