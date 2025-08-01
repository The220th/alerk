# coding: utf-8

from pydantic import BaseModel
from typing import List
import json
import os
# import base64
import random
import hashlib
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from alerk.crypto import bytes2str, str2bytes, asym_encrypt, asym_decrypt, gen_asym_keys, asym_sign, asym_verify, calc_key_hash


class MessageEn(BaseModel):
    h: str
    m: List[str]  # max len 214

    def to_json(self) -> str:
        d = {"h": self.h, "m": self.m}
        return json.dumps(d, indent=4)

    @staticmethod
    def from_json(json_str: str) -> "MessageEn":
        d = json.loads(json_str)
        return MessageEn(h=d["h"], m=d["m"])


class KMessage:

    def __init__(self, text: str, raws: list[tuple[str, bytes]]):
        """

        :param text: text of message
        :param raws: files. It is tuple of name and content. Name can be empty string. raws can be empty list ([])
        """
        self.text: str = text
        self.raws: list[tuple[str, bytes]] = raws
        self.pub_key_hash: str | None = None

    @staticmethod
    def _transform_raws(raws: list[tuple[str, bytes]]) -> list[list[str]]:
        res: list[list[str]] = []
        # raws = sorted(raws, key=lambda x: (x[0], x[1]))
        for raw_i in raws:
            res.append([raw_i[0], bytes2str(raw_i[1])])
        return res

    @staticmethod
    def _untransform_raws(raws: list[list[str]]) -> list[tuple[str, bytes]]:
        res: list[tuple[str, bytes]] = []
        for raw_i in raws:
            res.append((raw_i[0], str2bytes(raw_i[1])))
        # raws = sorted(raws, key=lambda x: (x[0], x[1]))
        return res

    def calc_hash(self) -> str:
        ho = hashlib.sha256()
        ho.update(self.text.encode(encoding="utf-8"))
        for raw_i in self.raws:
            ho.update(raw_i[0].encode(encoding="utf-8"))
            ho.update(raw_i[1])
        return ho.hexdigest()

    def to_dict(self, from_who_priv_sign_key: RSAPrivateKey, from_who_pub_sign_key: RSAPublicKey) -> dict:
        """

        :param from_who_priv_sign_key: Key to sign this message
        :param from_who_pub_sign_key: The key that will be used to verify the signature
        :return:
        """
        sign_key: RSAPrivateKey = from_who_priv_sign_key
        pub_key_hash: str = calc_key_hash(from_who_pub_sign_key)

        hash_b: bytes = self.calc_hash().encode(encoding="utf-8")
        hash_signed_b: bytes = asym_sign(hash_b, sign_key)
        hash_signed: str = bytes2str(hash_signed_b)

        res = {"text": self.text, "raws": KMessage._transform_raws(self.raws), "pub_key_hash": pub_key_hash, "sign": hash_signed}
        return res

    def to_json(self, from_who_priv_sign_key: RSAPrivateKey, from_who_pub_sign_key: RSAPublicKey) -> str:
        """

        :param from_who_priv_sign_key: Key to sign this message
        :param from_who_pub_sign_key: The key that will be used to verify the signature
        :return:
        """
        return json.dumps(self.to_dict(from_who_priv_sign_key, from_who_pub_sign_key), indent=4)

    @staticmethod
    def from_json(json_text: str, from_who_pub_sign_key: RSAPublicKey) -> "KMessage":
        """

        :param json_text: text of json
        :param from_who_pub_sign_key: The key that will be used to verify the signature
        :return:
        """
        d = json.loads(json_text)
        return KMessage.from_dict(d, from_who_pub_sign_key)

    @staticmethod
    def from_dict(d: dict, from_who_pub_sign_key: RSAPublicKey) -> "KMessage":
        """

        :param d: dict, what represents KMessage <- KMessage.to_dict(...)
        :param from_who_pub_sign_key:The key that will be used to verify the signature
        :return:
        """
        if "text" not in d or "raws" not in d or "pub_key_hash" not in d or "sign" not in d:
            raise ValueError("In dict must be all of these keys: [\"text\", \"raws\", \"pub_key_hash\", \"sign\", ]")

        text: str = d["text"]
        buff_raws: list[list[str]] = d["raws"]
        raws: list[tuple[str, bytes]] = KMessage._untransform_raws(buff_raws)

        pub_key_hash: str = d["pub_key_hash"]
        sign: bytes = str2bytes(d["sign"])
        if calc_key_hash(from_who_pub_sign_key) != pub_key_hash:
            raise ValueError("Wrong key")

        res = KMessage(text, raws)
        res.pub_key_hash = pub_key_hash

        hash_b = res.calc_hash().encode(encoding="utf-8")
        if not asym_verify(hash_b, sign, from_who_pub_sign_key):
            raise ValueError("Sign does not match!")

        return res

    def get_text(self) -> str:
        return self.text

    def get_raws(self) -> list[tuple[str, bytes]]:
        return self.raws

    def get_pub_sign_key_hash(self) -> str | None:
        return self.pub_key_hash

    def is_equal(self, kmsg2: "KMessage") -> bool:
        return self.calc_hash() == kmsg2.calc_hash()


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

    def get_data(self) -> dict[str: str] | MessageEn:
        return self.data

    def encrypt(self, pub_key: RSAPublicKey) -> "MessageContainer":
        """

        :param pub_key: key of the entity to which the message is sent
        :return:
        """
        if self.is_contains_decrypted():
            msgen = MessageContainer._to_en(self.data, pub_key)
            return MessageContainer(msgen)
        else:
            raise ValueError("This container contains already encrypted data.")

    def decrypt(self, priv_key: RSAPrivateKey) -> "MessageContainer":
        """

        :param priv_key: private key from the pair with the public key that encrypted this message
        :return:
        """
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
            # buffs = base64.b64encode(bs).decode(encoding="utf-8")
            buffs = bytes2str(bs)
            res.append(buffs)  # max len 214

        hash_object = hashlib.sha256()
        for bs_i in res:
            hash_object.update(bs_i.encode(encoding="utf-8"))
        salt = os.urandom(MessageContainer.SALT_SIZE)
        h_b = salt + hash_object.digest()
        h_b_en = asym_encrypt(h_b, pub_key)
        # h = base64.b64encode(h_b_en).decode(encoding="utf-8")
        h = bytes2str(h_b_en)

        mc = MessageEn(h=h, m=res)
        return mc

    @staticmethod
    def _to_de(men: MessageEn, priv_key: RSAPrivateKey) -> dict[str: str]:
        # h_b_en = base64.b64decode(men.h)
        h_b_en = str2bytes(men.h)
        h_b = asym_decrypt(h_b_en, priv_key)
        h_b = h_b[MessageContainer.SALT_SIZE:]

        hash_object = hashlib.sha256()
        for bs_i in men.m:
            hash_object.update(bs_i.encode(encoding="utf-8"))

        if h_b != hash_object.digest():
            raise ValueError(f"Hash does not match. May be wrong key or data?")

        byte_list = []
        for el_i in men.m:
            # bs = base64.b64decode(el_i)
            bs = str2bytes(el_i)
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
