# coding: utf-8

import telebot


def main(TOKEN: str):
    bot = telebot.TeleBot(TOKEN)

    @bot.message_handler(commands=['start', 'help'])
    def send_welcome(message):
        bot.reply_to(message, f"Your telegram ID: {message.from_user.id}")

    @bot.message_handler(func=lambda message: True)
    def echo_all(message):
        bot.reply_to(message, f"Your telegram ID: {message.from_user.id}")

    bot.infinity_polling()


if __name__ == "__main__":
    TOKEN = 'YOUR_BOT_TOKEN'
    TOKEN = input("Enter telegram bot token: ")
    main(TOKEN)
