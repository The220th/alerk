# coding: utf-8

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
from pydantic import ValidationError

from alerk.args_parsing import get_args
from alerk.setting_manager import SettingManager
from alerk.crypto import gen_asym_keys, asym_key_to_str, str_to_asym_key, compare_two_keys, calc_key_hash
from alerk.message import MessageEn


args = get_args()
if args.command == "gen_keys":
    col = "="*30
    sections = [f"\t\t\t\t\t{col}Encryption/Decryption{col}", f"\t\t\t\t\t{col}Sign/Verify{col}"]
    for i in range(2):
        print(sections[i])
        priv_key, pub_key = gen_asym_keys()
        priv_key_str = asym_key_to_str(priv_key)
        pub_key_str = asym_key_to_str(pub_key)
        assert compare_two_keys(str_to_asym_key(priv_key_str, False), priv_key)
        assert compare_two_keys(str_to_asym_key(pub_key_str, True), pub_key)
        print(f"Private key: \n{priv_key_str}")
        print(f"Private key hash: {calc_key_hash(priv_key)}")
        print(f"\nPublic key: \n{pub_key_str}")
        print(f"Public key hash: {calc_key_hash(pub_key)}\n")
    exit()
elif args.command == "test":
    from alerk.tests import cur_test
    cur_test()
    exit()
elif args.command == "start":
    pass
else:
    raise RuntimeError(f"WTF command \"args.command\"?")

setting_manager = SettingManager(args.settings_path)




app = FastAPI()


@app.post(setting_manager.get_endpoint())
def create_item(item: MessageEn):
    total_price = item.price * item.quantity
    response = {
        "name": item.name,
        "total_price": total_price
    }
    return response


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
