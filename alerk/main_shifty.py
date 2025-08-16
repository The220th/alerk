# coding: utf-8

import argparse

from alerk_pack.crypto import gen_asym_keys, asym_key_to_str, str_to_asym_key, compare_two_asym_keys, calc_asym_key_hash


def main_shifty(args: argparse.Namespace):
    if args.command == "gen_keys":
        col = "="*30
        sections = [f"\t\t\t\t\t{col}Encryption/Decryption{col}", f"\t\t\t\t\t{col}Sign/Verify{col}"]
        for i in range(2):
            print(sections[i])
            priv_key, pub_key = gen_asym_keys()
            priv_key_str = asym_key_to_str(priv_key)
            pub_key_str = asym_key_to_str(pub_key)
            assert compare_two_asym_keys(str_to_asym_key(priv_key_str, False), priv_key)
            assert compare_two_asym_keys(str_to_asym_key(pub_key_str, True), pub_key)
            print(f"Private key: \n{priv_key_str}")
            print(f"Private key hash: {calc_asym_key_hash(priv_key)}")
            print(f"\nPublic key: \n{pub_key_str}")
            print(f"Public key hash: {calc_asym_key_hash(pub_key)}\n")
        exit()
    elif args.command == "test":
        from alerk.tests import cur_test
        cur_test()
        exit()
    elif args.command == "start":
        pass
    else:
        raise RuntimeError(f"WTF command \"args.command\"?")
