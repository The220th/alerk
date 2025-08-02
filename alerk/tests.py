# coding: utf-8

import random

from alerk_pack.message import MessageEn, MessageContainer, KMessage
from alerk_pack.crypto import gen_asym_keys

def cur_test():
    test_k4hb1jB32()
    print("OK")

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


def test_k4hb1jB32():
    from ksupk import gen_random_string
    from tqdm import tqdm
    for _ in tqdm(range(1000)):
        priv_key1, pub_key1 = gen_asym_keys()  # sender
        priv_key2, pub_key2 = gen_asym_keys()  # receiver
        records = random.randint(4, 1000)

        text = gen_random_string(random.randint(0, 1000))
        raws = []
        while random.randint(0, 100) < 10:
            name = gen_random_string() if random.randint(0, 100) < 80 else ""
            content = gen_random_string(random.randint(0, 1000)).encode(encoding="utf-8")
            raws.append((name, content))
        kmsg1 = KMessage(text=text, raws=raws)
        d1 = kmsg1.to_dict(priv_key1, pub_key1)

        msgc1 = MessageContainer(d1)
        assert msgc1.is_contains_decrypted()
        msgc2 = msgc1.encrypt(pub_key2)
        assert msgc2.is_contains_encrypted()
        msgc3 = MessageContainer(msgc2.get_data())
        assert msgc3.is_contains_encrypted()
        msgc4 = msgc3.decrypt(priv_key2)
        assert msgc4.is_contains_decrypted()

        assert msgc4.get_data() == msgc1.get_data()

        d2 = msgc4.get_data()
        kmsg2 = KMessage.from_dict(d2, pub_key1)

        assert kmsg1.is_equal(kmsg2)
