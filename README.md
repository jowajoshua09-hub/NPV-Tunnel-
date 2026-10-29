# NPVS Decrypt Telegram Bot

Recover passwords for NapsternetV / NPV Tunnel `.npvs` backup files.

## Quick Start

```bash
# 1. Install dependencies
pip install pyTelegramBotAPI pycryptodome

# 2. Create a bot via @BotFather on Telegram, get the token

# 3. Run the bot
export BOT_TOKEN="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
python3 npvs_decrypt_bot.py
```

## Bot Commands

| Command | What it does |
|---|---|
| `/start` | Intro & instructions |
| Upload `.npvs` file | Loads & parses the backup |
| `/pw password123` | Try one specific password |
| `/pin` | Brute-force 4–6 digit numeric PINs |
| `/pin 4 8` | Brute-force 4 to 8 digits |
| `/dict` + upload `.txt` | Dictionary attack (one password per line) |
| `/status` | Check running job progress |
| `/cancel` | Stop the current job |

## How It Works

Reverse-engineered from NPV Tunnel v124:

- **Cipher**: AES-256-GCM (tries CBC as fallback)
- **KDF**: PBKDF2 — tries 11 combos (SHA256/SHA512/SHA1 × 1k/10k/65k/100k iterations × 128/256-bit keys)
- **Salt**: 7 variants (including `npvtunnel/kfold/salt/v1` found in the binary)
- **Validation**: Detects JSON / protobuf / printable plaintext
- On success: returns the password + full decrypted payload as a downloadable file

## Important Notes

- If the password is a **4–6 digit PIN**, brute-force is fast (1.1M combos, ~minutes).
- If it's a **longer alphanumeric passphrase**, use `/dict` with a wordlist — pure brute-force is infeasible.
- If no KDF combo matches, the app may use custom parameters — the code is easy to extend (edit `PBKDF2_PARAMS` and `SALT_VARIANTS`).
- Only use this on **your own** backup files.
-
