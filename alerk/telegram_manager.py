# coding: utf-8

import telebot
from threading import Lock
from ksupk import singleton_decorator
from io import BytesIO


@singleton_decorator
class TelegramManager:

    def __init__(self, token: str):
        self.token: str = token
        self._gl_lock = Lock()

    def send_text(self, telegram_user_id: int, message: str):
        with self._gl_lock:
            bot = telebot.TeleBot(self.token)

            bot.send_message(telegram_user_id, message)

    def send_files(self, telegram_user_id: int, files: list[tuple[str, bytes]]):
        with self._gl_lock:
            bot = telebot.TeleBot(self.token)

            for file_i in files:
                try:
                    file_name, file_content = file_i[0], file_i[1]
                    file_stream = BytesIO(file_content)
                    file_stream.name = file_name
                    file_stream.seek(0)
                    bot.send_document(telegram_user_id, file_stream, caption=file_name)
                except Exception as e:
                    bot.send_message(telegram_user_id, "Cannot send file.")
