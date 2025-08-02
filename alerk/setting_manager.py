# coding: utf-8

import yaml
from pathlib import Path
from ksupk import singleton_decorator

from alerk.smalk import Smalk


@singleton_decorator
class SettingManager:

    def __init__(self, settings_yaml_path: Path | str):
        settings_yaml_path = Path(settings_yaml_path)

        with open(settings_yaml_path, 'r', encoding="utf-8") as file:
            data = yaml.safe_load(file)

        self.data: dict = dict(data)

    def get_endpoint(self) -> str:
        return self.data["app"]["endpoint"]

    def get_uvicorn_settings(self) -> dict[str: str | int]:
        res = {
                "host": self.data["uvicorn"]["inf"],
                "port": self.data["uvicorn"]["port"],
                "log_level": self.data["uvicorn"]["log_level"]
               }
        return res

    #              ==================== keys ====================

    def get_priv_key(self) -> str:
        return self.data["keys"]["priv_key"]

    def get_pub_key(self) -> str:
        return self.data["keys"]["pub_key"]

    def get_sign_key(self) -> str:
        return self.data["keys"]["sign_key"]

    def get_verify_key(self) -> str:
        return self.data["keys"]["verify_key"]

    #              ==================== telegram ====================

    def get_telegram_token(self) -> str:
        return self.data["telegram"]["token"]

    def get_telegram_allowed_users_id(self) -> list[int]:
        return self.data["telegram"]["allowed_users"]

    #              ==================== smalk ====================

    def get_smalks(self) -> list[Smalk]:
        res: list[Smalk] = []
        smalks = self.data["smalk"]
        for smalk_i in smalks:
            code, pub_key, verify_key = smalk_i["code"], smalk_i["pub_key"], smalk_i["verify_key"]
            res.append(Smalk(code=code, pub_key=pub_key, verify_key=verify_key))
        return res