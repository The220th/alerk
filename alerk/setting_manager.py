# coding: utf-8

import yaml
from pathlib import Path
from ksupk import singleton_decorator

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
