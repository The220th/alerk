# coding: utf-8

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from alerk_pack.message import MessageEn, MessageContainer, KMessage, MessageWrapper
from alerk.setting_manager import SettingManager
from alerk.telegram_manager import TelegramManager
from alerk.key_manager import KeyManager
from alerk.smalk import Smalk


def process_responce_main(msg: MessageEn) -> MessageEn:
    req, smalk = process_responce_decrypt(msg)
    answer = process_responce_form_answer(req, smalk)
    to_send: MessageEn = process_responce_encrypt(answer, smalk)
    return to_send


def process_responce_decrypt(msg: MessageEn) -> tuple[KMessage, Smalk]:
    key_manager = KeyManager()
    priv_key: RSAPrivateKey = key_manager.get_priv_key()
    msg_container_en = MessageContainer(msg)
    msg_container_de = msg_container_en.decrypt(priv_key)
    d = msg_container_de.get_data()
    from_smalk = key_manager.get_smalk_by_hash(KMessage.get_pub_key_hash(d))
    verif_key: RSAPublicKey = from_smalk.get_verify_key()
    res: KMessage = KMessage.from_dict(d, verif_key)
    return res, from_smalk


def process_responce_encrypt(msg: KMessage, to_whom: Smalk) -> MessageEn:
    key_manager = KeyManager()
    d = msg.to_dict(key_manager.get_sign_key(), key_manager.get_verify_key())
    msg_container_de = MessageContainer(d)
    msg_container_en = msg_container_de.encrypt(to_whom.get_pub_key())
    res: MessageEn = msg_container_en.get_data()
    return res


def process_responce_form_answer(msg: KMessage, from_whom: Smalk) -> KMessage:
    text = msg.get_text()
    raws = msg.get_raws()

    mw: MessageWrapper = MessageWrapper.from_json(text)
    if mw.get_type() == MessageWrapper.MSG_TYPE_REPORT:
        tm = TelegramManager()
        sm = SettingManager()
        t_users = sm.get_telegram_allowed_users_id()

        msg_text = f"{from_whom.get_code()} says: \"{mw.get_text()}\""
        for t_user_i in t_users:
            tm.send_text(t_user_i, msg_text)
            if mw.is_attachments():
                tm.send_files(t_user_i, raws)
        text = MessageWrapper(msg_type=MessageWrapper.MSG_TYPE_OK, text="", is_attachments=False).to_json()
        kmsg = KMessage(text=text, raws=[])
        return kmsg
    else:
        text = MessageWrapper(msg_type=MessageWrapper.MSG_TYPE_ERROR, text="", is_attachments=False).to_json()
        kmsg = KMessage(text=text, raws=[])
        return kmsg
