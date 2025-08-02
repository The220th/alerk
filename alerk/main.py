# coding: utf-8

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
from pydantic import ValidationError

from alerk.main_shifty import main_shifty
from alerk.process_responce import process_responce_main
from alerk.args_parsing import get_args
from alerk.setting_manager import SettingManager
from alerk_pack.message import MessageEn
from alerk.telegram_manager import TelegramManager
from alerk.key_manager import KeyManager


args = get_args()

main_shifty(args)

setting_manager = SettingManager(args.settings_path)
telegram_manager = TelegramManager(setting_manager.get_telegram_token())
key_manager = KeyManager(setting_manager)


app = FastAPI()


@app.post(setting_manager.get_endpoint())
def process_main(msg_in: MessageEn) -> MessageEn:
    msg_out = process_responce_main(msg_in)
    return msg_out


@app.exception_handler(ValidationError)
def validation_exception_handler(request, exc: ValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )

def main():
    global args
    global setting_manager
    sm = setting_manager
    uvicorn_settings = sm.get_uvicorn_settings()
    uvicorn.run(
        app,
        host=uvicorn_settings["host"],
        port=uvicorn_settings["port"],
        log_level=uvicorn_settings["log_level"]
    )


if __name__ == "__main__":
    main()
