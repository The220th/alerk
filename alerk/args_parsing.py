# coding: utf-8

import argparse
from alerk import __version__


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="alerk is server of notifications. ")

    parser.add_argument("--version", action="version", version=f"V{__version__}", help="Check version. ")

    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start", help="Start it")

    start_parser.add_argument("settings_path", type=str, help="Path to yaml file with settings. ")


    gen_keys_parser = subparsers.add_parser("gen_keys", help="generate keys")

    # test_parser = subparsers.add_parser("test", help="???")

    return parser.parse_args()
