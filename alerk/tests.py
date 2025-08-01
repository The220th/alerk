# coding: utf-8

import random

from alerk.message import MessageEn, MessageContainer
from alerk.crypto import gen_asym_keys

def cur_test():
    test_ejh3jvnnbt()

def test_ejh3jvnnbt():
    from ksupk import gen_random_string
    from tqdm import tqdm
    for _ in tqdm(range(1000)):
        priv_key, pub_key = gen_asym_keys()
        records = random.randint(4, 1000)
        d = {}
        for __ in range(records):
            rnd_str = gen_random_string()
            d[rnd_str] = gen_random_string(random.randint(0, 1000))

        msgc1 = MessageContainer(d)
        assert msgc1.is_contains_decrypted()
        msgc2 = msgc1.encrypt(pub_key)
        assert msgc2.is_contains_encrypted()
        msgc3 = MessageContainer(msgc2.get_data())
        assert msgc3.is_contains_encrypted()
        msgc4 = msgc3.decrypt(priv_key)
        assert msgc4.is_contains_decrypted()

        assert msgc4.get_data() == msgc1.get_data()
