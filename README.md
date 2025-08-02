# alerk

`alerk`, if **aler**t, reports on events.

![](imgs/intro.drawio.png)

# Info

**READ THIS SECTION FIRST**

There are two entities:

- `alerk`: This is the server to which the `smalk`s broadcast.

- `smalk`: This is clients/notifiers, which trigger to some event and send it to `alerk`.

Known smalks:

- comming soon maybe=/

## Current way to notify

- `Telegram`. 

Perhaps there will be other ways in the future.

## Why alerk/smalk

- Easy set up.

- Cryptography (RSA4096) is in the box. Messages are transmitted through a secure tunnel.

- There is a verification of the sender (signature). That is, only your `smalk` will be able to report events to your `alerk`.

- No need ssl.

- You can easily write your own [`smalk`](#writing-your-own-smalk).

# Installing

```bash
pip3 install alerk
```

# Setting up

## Create yaml setting file

Clone it from `settings_template.yaml`.

## Set up telegram bot

You can get `token` from `@BotFather` (it is telegram bot).
Input this `token` to yaml setting file.
Run script from `extra/warm_up_telebot.py`. Do `/start` from needed telegram users and remember their `telegram id`.
Input this `telegram id` to yaml setting file.

## Set up keys

Generate keys of `alerk`:

```bash
alerk gen_keys
```

Put this keys to yaml setting file.

Do it for each `smalk`. Put their keys in their configuration files, as well as only their public keys in yaml setting file.

## Set up other settings

Read all yaml setting file and change needed fields.

# Run

```bash
alerk start /path/to/your/yaml/setting/file
```

# Writing your own smalk

Examine the file `extra/smalk_base.py`.
