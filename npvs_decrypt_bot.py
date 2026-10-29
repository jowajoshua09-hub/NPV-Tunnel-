#!/usr/bin/env python3
"""
NPVS Decrypt Telegram Bot
=========================
A Telegram bot for recovering/decrypting NapsternetV (NPV Tunnel) .npvs
backup files. Reverse-engineered from the NPV Tunnel app (v124.x).

Confirmed crypto scheme (from libgojni.so + JNI API):
  - Cipher: AES-256-GCM
  - Passphrase KDF: PBKDF2 (domain sep: "npvtunnel/kfold/salt/v1")
  - Envelope encryption: random DEK -> wrapped by passphrase-derived key
  - JNI entry: openPassphraseToDeviceConfigs(byte[], byte[], byte[], long)

The bot tries multiple PBKDF2 parameter combinations + candidate ciphertext
regions and validates decryption by detecting JSON/protobuf/printable output.

Usage:
  pip install pyTelegramBotAPI pycryptodome
  export BOT_TOKEN="your-telegram-bot-token"
  python3 npvs_decrypt_bot.py

Bot commands:
  /start        - intro & instructions
  /pin <4-6>    - brute-force numeric PIN (default 4-6 digits)
  /dict <file>  - dictionary attack (upload a wordlist .txt)
  /pw <pass>    - try a single password
  /status       - show current job status
  /cancel       - cancel running job
"""

import os
import io
import struct
import json
import time
import string
import threading
import itertools
from hashlib import pbkdf2_hmac, sha256, sha512, md5

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

try:
    import telebot
    from telebot import types
except ImportError:
    raise SystemExit("Install deps: pip install pyTelegramBotAPI pycryptodome flask")

# Minimal Flask server so this can run as a Render FREE Web Service
# (Web Services require an open HTTP port; the bot runs in a bg thread).
try:
    from flask import Flask
    _flask = Flask(__name__)

    @_flask.route("/")
    @_flask.route("/health")
    def _health():
        return "ok", 200
except ImportError:
    _flask = None

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
if not BOT_TOKEN:
    raise SystemExit("Set BOT_TOKEN env var (from @BotFather)")

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML")

# ---------------------------------------------------------------------------
# NPVS file parser (reverse-engineered structure)
# ---------------------------------------------------------------------------
MAGIC = b"NPVS"
NPF_MARKER = b"NPF"

class NpvsFile:
    def __init__(self, data: bytes):
        self.raw = data
        self.magic = data[:4]
        self.version = data[4]  # e.g. 5
        self.entries = []       # list of (idx, length, payload_bytes)
        self.header_enc = b""
        self.subheader_enc = b""
        self.trailing = b""
        self._parse()

    def _parse(self):
        data = self.raw
        npf_pos = data.find(NPF_MARKER)
        if npf_pos < 0:
            raise ValueError("Not an NPVS file (no NPF marker)")
        self.header_enc = data[8:npf_pos]  # encrypted header block
        # after NPF marker (3 bytes) -> encrypted sub-header until entries start
        # scan for sequential 4-byte LE indices starting at 1
        entries_start = self._find_entries_start(data, npf_pos + 3)
        self.subheader_enc = data[npf_pos+3:entries_start]
        pos = entries_start
        expected = 1
        while pos + 5 <= len(data):
            idx = struct.unpack_from("<I", data, pos)[0]
            if idx != expected:
                if data[pos] == 0:
                    pos += 1
                    continue
                break
            length = data[pos+4]
            if length == 0 or pos + 5 + length > len(data):
                break
            payload = data[pos+5:pos+5+length]
            self.entries.append((idx, length, payload))
            pos += 5 + length + 1  # +1 for 0x00 separator
            expected += 1
        self.trailing = data[pos:]

    @staticmethod
    def _find_entries_start(data: bytes, min_pos: int) -> int:
        for off in range(min_pos, min(min_pos + 80, len(data) - 8)):
            if struct.unpack_from("<I", data, off)[0] == 1:
                # verify next few entries are sequential
                p = off + 5 + data[off+4] + 1
                ok = True
                for i in range(2, 5):
                    if p + 5 > len(data) or struct.unpack_from("<I", data, p)[0] != i:
                        ok = False
                        break
                    p += 5 + data[p+4] + 1
                if ok:
                    return off
        return min_pos + 36  # fallback

    def summary(self) -> str:
        lens = [e[1] for e in self.entries]
        return (
            f"Magic: {self.magic.decode()}  |  Version: {self.version}\n"
            f"Config entries: {len(self.entries)}\n"
            f"Entry sizes: min={min(lens)} max={max(lens)} avg={sum(lens)/len(lens):.0f} bytes\n"
            f"Encrypted header: {len(self.header_enc)} bytes\n"
            f"Trailing block: {len(self.trailing)} bytes\n"
            f"Total file: {len(self.raw)} bytes"
        )

    def candidate_ciphertexts(self):
        """Yield (label, iv, ciphertext+tag) regions to try decryption on."""
        # AES-GCM: typically IV(12) + ciphertext + tag(16)
        # Try the header block
        h = self.header_enc
        if len(h) >= 28:
            yield ("header_iv12", h[:12], h[12:])
        # Try trailing block
        t = self.trailing
        if len(t) >= 28:
            yield ("trailing_iv12", t[:12], t[12:])
        # Try concatenation of all entry payloads (body)
        body = b"".join(e[2] for e in self.entries)
        if len(body) >= 28:
            yield ("entries_body_iv12", body[:12], body[12:])
        # Try first few individual entries (if large enough)
        for idx, length, pl in self.entries[:5]:
            if length >= 28:
                yield (f"entry{idx}_iv12", pl[:12], pl[12:])
        # Try IV=0 (some apps use zero nonce)
        zero_iv = b"\x00" * 12
        if len(h) >= 16:
            yield ("header_zeroiv", zero_iv, h)
        if len(t) >= 16:
            yield ("trailing_zeroiv", zero_iv, t)


# ---------------------------------------------------------------------------
# Decryption engine
# ---------------------------------------------------------------------------
PBKDF2_PARAMS = [
    # (hash_name, iterations, key_len)
    ("sha256", 1000, 32),
    ("sha256", 10000, 32),
    ("sha256", 65536, 32),
    ("sha256", 100000, 32),
    ("sha512", 1000, 32),
    ("sha512", 10000, 32),
    ("sha512", 65536, 32),
    ("sha1", 1000, 32),
    ("sha1", 10000, 32),
    ("sha256", 10000, 16),   # AES-128 fallback
    ("sha256", 65536, 16),
]

SALT_VARIANTS = [
    b"npvtunnel/kfold/salt/v1",
    b"",
    b"npvs",
    b"NPVS",
    b"napsternetv",
    b"vonmatrix",
    b"npvtunnel",
]

def looks_like_plaintext(blob: bytes) -> bool:
    """Heuristic: does this look like decrypted JSON/protobuf/text?"""
    if not blob:
        return False
    # JSON?
    s = blob.strip()
    if s[:1] in (b"{", b"[") and s[-1:] in (b"}", b"]"):
        try:
            json.loads(s.decode("utf-8", errors="strict"))
            return True
        except Exception:
            pass
    # Mostly printable ASCII?
    printable = sum(1 for b in blob if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(blob) > 0.85 and len(blob) > 8:
        return True
    # Protobuf-like: starts with small field tag
    if len(blob) > 2 and blob[0] < 0x20 and blob[1] < 0x80:
        # check second byte is reasonable length
        if blob[1] < len(blob):
            return True
    return False

def try_decrypt(npvs: NpvsFile, password: str) -> dict | None:
    """Try all param combos. Returns result dict on success, None otherwise."""
    pw_bytes = password.encode("utf-8")
    for hash_name, iters, key_len in PBKDF2_PARAMS:
        for salt in SALT_VARIANTS:
            try:
                key = pbkdf2_hmac(hash_name, pw_bytes, salt, iters, dklen=key_len)
            except Exception:
                continue
            for label, iv, ct in npvs.candidate_ciphertexts():
                if len(ct) < 16:
                    continue
                # AES-GCM: tag is last 16 bytes
                ciphertext = ct[:-16]
                tag = ct[-16:]
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    if looks_like_plaintext(plaintext):
                        return {
                            "password": password,
                            "hash": hash_name,
                            "iterations": iters,
                            "key_len": key_len * 8,
                            "salt": salt.decode("latin-1", errors="replace"),
                            "region": label,
                            "plaintext_preview": plaintext[:200].decode("utf-8", errors="replace"),
                            "plaintext_full": plaintext,
                        }
                except Exception:
                    pass
                # Also try AES-CBC (fallback)
                if len(ct) >= 16 and len(ct) % 16 == 0:
                    try:
                        cipher = AES.new(key, AES.MODE_CBC, iv=iv[:16])
                        pt = unpad(cipher.decrypt(ct), 16)
                        if looks_like_plaintext(pt):
                            return {
                                "password": password, "hash": hash_name,
                                "iterations": iters, "key_len": key_len * 8,
                                "salt": salt.decode("latin-1", errors="replace"),
                                "region": label + "_CBC",
                                "plaintext_preview": pt[:200].decode("utf-8", errors="replace"),
                                "plaintext_full": pt,
                            }
                    except Exception:
                        pass
    return None


# ---------------------------------------------------------------------------
# Job state (per-user)
# ---------------------------------------------------------------------------
jobs = {}  # chat_id -> {"npvs": NpvsFile, "thread": Thread, "cancel": bool, "status": str}

def set_status(chat_id, msg):
    if chat_id in jobs:
        jobs[chat_id]["status"] = msg

def run_pin_bruteforce(chat_id, npvs: NpvsFile, min_digits=4, max_digits=6):
    """Brute-force numeric PINs."""
    j = jobs[chat_id]
    total = sum(10**d for d in range(min_digits, max_digits + 1))
    tried = 0
    found = None
    for digits in range(min_digits, max_digits + 1):
        for pin_tuple in itertools.product("0123456789", repeat=digits):
            if j["cancel"]:
                bot.send_message(chat_id, "⛔ Cancelled by user.")
                return
            pin = "".join(pin_tuple)
            tried += 1
            if tried % 500 == 0:
                set_status(chat_id, f"PIN brute-force: {tried}/{total} tried (currently {digits} digits, last: {pin})")
            result = try_decrypt(npvs, pin)
            if result:
                found = result
                break
        if found:
            break
    if found:
        msg = (
            f"✅ <b>PASSWORD FOUND</b>\n\n"
            f"Password: <code>{found['password']}</code>\n"
            f"KDF: PBKDF2-{found['hash'].upper()} {found['iterations']} iters, {found['key_len']}-bit key\n"
            f"Salt: <code>{found['salt']}</code>\n"
            f"Region: {found['region']}\n\n"
            f"<b>Plaintext preview:</b>\n<pre>{found['plaintext_preview'][:500]}</pre>"
        )
        bot.send_message(chat_id, msg)
        # Send full plaintext as file
        bio = io.BytesIO(found["plaintext_full"])
        bio.name = "decrypted_config.txt"
        bot.send_document(chat_id, bio, caption="Full decrypted payload")
    else:
        bot.send_message(chat_id, f"❌ PIN brute-force complete ({tried} tried). No match. Try /dict with a wordlist or longer PIN range.")
    j["thread"] = None
    j["status"] = "idle"

def run_dict_attack(chat_id, npvs: NpvsFile, words: list[str]):
    j = jobs[chat_id]
    found = None
    for i, w in enumerate(words):
        if j["cancel"]:
            bot.send_message(chat_id, "⛔ Cancelled by user.")
            return
        if i % 100 == 0:
            set_status(chat_id, f"Dictionary: {i}/{len(words)} tried (last: {w[:20]})")
        result = try_decrypt(npvs, w)
        if result:
            found = result
            break
    if found:
        msg = (
            f"✅ <b>PASSWORD FOUND</b>\n\n"
            f"Password: <code>{found['password']}</code>\n"
            f"KDF: PBKDF2-{found['hash'].upper()} {found['iterations']} iters, {found['key_len']}-bit key\n"
            f"Salt: <code>{found['salt']}</code>\n\n"
            f"<b>Preview:</b>\n<pre>{found['plaintext_preview'][:500]}</pre>"
        )
        bot.send_message(chat_id, msg)
        bio = io.BytesIO(found["plaintext_full"])
        bio.name = "decrypted_config.txt"
        bot.send_document(chat_id, bio, caption="Full decrypted payload")
    else:
        bot.send_message(chat_id, f"❌ Dictionary attack complete ({len(words)} words). No match.")
    j["thread"] = None
    j["status"] = "idle"


# ---------------------------------------------------------------------------
# Telegram handlers
# ---------------------------------------------------------------------------
@bot.message_handler(commands=["start", "help"])
def cmd_start(m):
    bot.reply_to(m,
        "🔓 <b>NPVS Decrypt Bot</b>\n\n"
        "Recover passwords for NapsternetV / NPV Tunnel <code>.npvs</code> backup files.\n\n"
        "<b>How to use:</b>\n"
        "1️⃣ Upload your <code>.npvs</code> file\n"
        "2️⃣ Choose an attack mode:\n"
        "   • <code>/pw password</code> — try one password\n"
        "   • <code>/pin</code> — brute-force 4-6 digit PINs (default)\n"
        "   • <code>/pin 4 8</code> — brute-force 4 to 8 digits\n"
        "   • <code>/dict</code> — then upload a <code>.txt</code> wordlist\n"
        "3️⃣ <code>/status</code> — check progress · <code>/cancel</code> — stop\n\n"
        "Crypto: AES-256-GCM + PBKDF2 (reverse-engineered from NPV Tunnel v124). "
        "Tries 11 KDF param combos × 7 salt variants automatically."
    )

@bot.message_handler(content_types=["document"])
def handle_file(m):
    cid = m.chat.id
    fname = (m.document.file_name or "").lower()
    if fname.endswith(".npvs"):
        file_info = bot.get_file(m.document.file_id)
        dl = bot.download_file(file_info.file_path)
        try:
            npvs = NpvsFile(dl)
        except Exception as e:
            bot.reply_to(m, f"❌ Parse error: {e}")
            return
        jobs[cid] = {"npvs": npvs, "thread": None, "cancel": False, "status": "file loaded", "dict_mode": False}
        bot.reply_to(m,
            f"📥 <b>NPVS file loaded</b>\n\n{npvs.summary()}\n\n"
            "Now choose:\n"
            "• <code>/pw yourpassword</code> — try one password\n"
            "• <code>/pin</code> — brute-force numeric PIN\n"
            "• <code>/dict</code> — dictionary attack (then send wordlist .txt)"
        )
    elif fname.endswith(".txt") and cid in jobs and jobs[cid].get("dict_mode"):
        file_info = bot.get_file(m.document.file_id)
        dl = bot.download_file(file_info.file_path)
        words = [w.strip() for w in dl.decode("utf-8", errors="replace").splitlines() if w.strip()]
        jobs[cid]["dict_mode"] = False
        bot.reply_to(m, f"📚 Wordlist loaded: {len(words)} words. Starting dictionary attack...")
        t = threading.Thread(target=run_dict_attack, args=(cid, jobs[cid]["npvs"], words), daemon=True)
        jobs[cid]["thread"] = t
        t.start()
    else:
        bot.reply_to(m, "📎 Upload a <code>.npvs</code> file first, or a <code>.txt</code> wordlist after <code>/dict</code>.")

@bot.message_handler(commands=["pw"])
def cmd_pw(m):
    cid = m.chat.id
    if cid not in jobs or "npvs" not in jobs[cid]:
        bot.reply_to(m, "⚠️ Upload a .npvs file first.")
        return
    parts = m.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(m, "Usage: <code>/pw yourpassword</code>")
        return
    pw = parts[1]
    bot.reply_to(m, f"🔑 Trying password: <code>{pw}</code> ...")
    result = try_decrypt(jobs[cid]["npvs"], pw)
    if result:
        msg = (f"✅ <b>SUCCESS</b>\n\nPassword: <code>{result['password']}</code>\n"
               f"KDF: PBKDF2-{result['hash'].upper()} {result['iterations']} iters, {result['key_len']}-bit key\n"
               f"Salt: <code>{result['salt']}</code>\nRegion: {result['region']}\n\n"
               f"<b>Preview:</b>\n<pre>{result['plaintext_preview'][:500]}</pre>")
        bot.send_message(cid, msg)
        bio = io.BytesIO(result["plaintext_full"])
        bio.name = "decrypted_config.txt"
        bot.send_document(cid, bio, caption="Full decrypted payload")
    else:
        bot.send_message(cid, f"❌ Password <code>{pw}</code> did not match any KDF parameter combo.")

@bot.message_handler(commands=["pin"])
def cmd_pin(m):
    cid = m.chat.id
    if cid not in jobs or "npvs" not in jobs[cid]:
        bot.reply_to(m, "⚠️ Upload a .npvs file first.")
        return
    if jobs[cid].get("thread") and jobs[cid]["thread"].is_alive():
        bot.reply_to(m, "⚠️ A job is already running. /cancel first.")
        return
    parts = m.text.split()
    mn, mx = 4, 6
    if len(parts) >= 3:
        try:
            mn, mx = int(parts[1]), int(parts[2])
        except ValueError:
            pass
    jobs[cid]["cancel"] = False
    total = sum(10**d for d in range(mn, mx + 1))
    bot.reply_to(m, f"🎯 PIN brute-force started: {mn}-{mx} digits ({total} combinations).\nUse /status to check progress, /cancel to stop.")
    t = threading.Thread(target=run_pin_bruteforce, args=(cid, jobs[cid]["npvs"], mn, mx), daemon=True)
    jobs[cid]["thread"] = t
    t.start()

@bot.message_handler(commands=["dict"])
def cmd_dict(m):
    cid = m.chat.id
    if cid not in jobs or "npvs" not in jobs[cid]:
        bot.reply_to(m, "⚠️ Upload a .npvs file first.")
        return
    jobs[cid]["dict_mode"] = True
    bot.reply_to(m, "📚 Dictionary mode active. Now upload a <code>.txt</code> wordlist (one password per line).")

@bot.message_handler(commands=["status"])
def cmd_status(m):
    cid = m.chat.id
    if cid in jobs:
        j = jobs[cid]
        running = j.get("thread") and j["thread"].is_alive()
        bot.reply_to(m, f"📊 Status: {j.get('status','idle')}\nJob running: {'✅ yes' if running else '❌ no'}")
    else:
        bot.reply_to(m, "No file loaded.")

@bot.message_handler(commands=["cancel"])
def cmd_cancel(m):
    cid = m.chat.id
    if cid in jobs:
        jobs[cid]["cancel"] = True
        bot.reply_to(m, "🚫 Cancel signal sent.")
    else:
        bot.reply_to(m, "Nothing to cancel.")

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("🤖 NPVS Decrypt Bot starting...")
    # Run Telegram polling in a background daemon thread
    bot_thread = threading.Thread(
        target=lambda: bot.infinity_polling(timeout=30, long_polling_timeout=30),
        daemon=True,
    )
    bot_thread.start()
    if _flask is not None:
        port = int(os.environ.get("PORT", 5000))
        print(f"🌐 Flask health server on port {port} (for Render Web Service)")
        print("💡 Keep alive: ping /health every ~10 min with UptimeRobot/cron-job.org")
        _flask.run(host="0.0.0.0", port=port)
    else:
        print("Flask not installed — running polling only (Worker mode).")
        bot_thread.join()
