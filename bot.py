import os
import re
import json
import base64
import binascii
import hashlib
import discord
from discord.ext import commands

TOKEN = os.getenv("DISCORD_TOKEN")
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", str(5 * 1024 * 1024)))
PREFIX = os.getenv("PREFIX", "!")
CONFIG_FILE = "config.json"

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents)

WEBHOOK_RE = re.compile(
    r"https?://(?:discord(?:app)?\.com|canary\.discord(?:app)?\.com|ptb\.discord(?:app)?\.com)"
    r"/api/webhooks/\d+/[A-Za-z0-9._~+/=-]+", re.I
)

KEYLOGGER = {
    "GetAsyncKeyState": re.compile(r"\bGetAsyncKeyState\b", re.I),
    "GetKeyState": re.compile(r"\bGetKeyState\b", re.I),
    "SetWindowsHookEx": re.compile(r"\bSetWindowsHookEx(?:A|W)?\b", re.I),
    "GetForegroundWindow": re.compile(r"\bGetForegroundWindow\b", re.I),
    "RegisterRawInputDevices": re.compile(r"\bRegisterRawInputDevices\b", re.I),
    "keylogger": re.compile(r"\bkey[\s_-]*logger\b", re.I),
    "keyboard": re.compile(r"\bkeyboard\b", re.I),
    "user32": re.compile(r"\buser32(?:\.dll)?\b", re.I),
    "io.read": re.compile(r"\bio\s*\.\s*read\s*\(", re.I),
}

EXECUTION = {
    "loadstring": re.compile(r"\bloadstring\s*\(", re.I),
    "load": re.compile(r"\bload\s*\(", re.I),
    "dofile": re.compile(r"\bdofile\s*\(", re.I),
    "loadfile": re.compile(r"\bloadfile\s*\(", re.I),
}

DECODE = {
    "string.char": re.compile(r"\bstring\s*\.\s*char\s*\(", re.I),
    "string.byte": re.compile(r"\bstring\s*\.\s*byte\s*\(", re.I),
    "string.reverse": re.compile(r"\bstring\s*\.\s*reverse\s*\(", re.I),
    "base64": re.compile(r"\b(?:base64|b64|decode64|frombase64)\b", re.I),
    "hex": re.compile(r"\b(?:hex|fromhex|unhex)\b", re.I),
}

def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def normalize(text):
    text = text.replace("\x00", " ")
    text = re.sub(r"--\[\[.*?\]\]", " ", text, flags=re.S)
    text = re.sub(r"--[^\r\n]*", " ", text)
    return text

def printable(data):
    return data.decode("utf-8", errors="ignore")

def decoded_candidates(text):
    result = []
    for token in re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])", text):
        try:
            result.append(printable(base64.b64decode(token + "=" * (-len(token) % 4), validate=True)))
        except Exception:
            pass

    for token in re.findall(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){20,}(?![0-9A-Fa-f])", text):
        try:
            result.append(printable(binascii.unhexlify(token)))
        except Exception:
            pass

    return result

def scan_lua(text):
    text = normalize(text)
    findings = []
    seen = set()

    def add(sev, msg):
        if msg not in seen:
            seen.add(msg)
            findings.append((sev, msg))

    if WEBHOOK_RE.search(text):
        add("CRITICAL", "Discord Webhook URL terdeteksi")

    for name, rx in KEYLOGGER.items():
        if rx.search(text):
            add("HIGH", f"Indikator keylogger/input: {name}")

    for name, rx in EXECUTION.items():
        if rx.search(text):
            add("MEDIUM", f"Dynamic code execution: {name}")

    for name, rx in DECODE.items():
        if rx.search(text):
            add("INFO", f"String/encoding technique: {name}")

    for decoded in decoded_candidates(text):
        if WEBHOOK_RE.search(decoded):
            add("CRITICAL", "Discord Webhook ditemukan setelah decoding")
        for name, rx in KEYLOGGER.items():
            if rx.search(decoded):
                add("CRITICAL", f"Indikator keylogger ditemukan setelah decoding: {name}")

    has_keylogger = any(
        "keylogger" in msg.lower() or "input" in msg.lower()
        for _, msg in findings
    )
    has_webhook = any("webhook" in msg.lower() for _, msg in findings)

    return findings, has_keylogger, has_webhook

def make_embed(filename, sha256, findings, has_keylogger, has_webhook):
    dangerous = has_keylogger or has_webhook

    if dangerous:
        title = "🚨 FILE TERDETEKSI MENCURIGAKAN"
        status = "Keylogger / Webhook terdeteksi"
    else:
        title = "✅ FILE AMAN"
        status = "File tidak ada keylogger file aman"

    embed = discord.Embed(title=title)
    embed.add_field(name="File", value=f"`{filename}`", inline=False)
    embed.add_field(name="Status", value=status, inline=False)
    embed.add_field(name="SHA-256", value=f"`{sha256}`", inline=False)

    if findings:
        text = "\n".join(f"• **{sev}** — {msg}" for sev, msg in findings[:20])
    else:
        text = "Tidak ditemukan indikator keylogger atau Discord webhook."

    embed.add_field(name="Hasil Scan", value=text[:1024], inline=False)
    embed.set_footer(text="#SANZZLUAONTOP • Static Scanner • Lua tidak dieksekusi")
    return embed

async def scan_attachment(message, attachment):
    if not attachment.filename.lower().endswith(".lua"):
        return

    if attachment.size > MAX_FILE_SIZE:
        await message.channel.send(
            f"❌ `{attachment.filename}` terlalu besar. Maksimum {MAX_FILE_SIZE // (1024*1024)} MB."
        )
        return

    status_msg = await message.channel.send(
        f"🔎 Sedang scan `{attachment.filename}`..."
    )

    try:
        data = await attachment.read()
        text = printable(data)
        sha256 = hashlib.sha256(data).hexdigest()

        findings, has_keylogger, has_webhook = scan_lua(text)
        embed = make_embed(
            attachment.filename,
            sha256,
            findings,
            has_keylogger,
            has_webhook
        )

        await status_msg.edit(content=None, embed=embed)

    except Exception as e:
        await status_msg.edit(
            content=f"❌ Gagal scan `{attachment.filename}`: `{type(e).__name__}`"
        )

@bot.event
async def on_ready():
    print(f"Bot aktif sebagai {bot.user} ({bot.user.id})")

@bot.command()
@commands.has_permissions(manage_guild=True)
async def setchannel(ctx):
    cfg = load_config()
    cfg[str(ctx.guild.id)] = ctx.channel.id
    save_config(cfg)

    await ctx.send(
        f"✅ **Auto-scan aktif!**\n"
        f"Semua file `.lua` yang di-upload di {ctx.channel.mention} akan otomatis discan.\n"
        f"**#SANZZLUAONTOP**"
    )

@bot.command()
@commands.has_permissions(manage_guild=True)
async def disablechannel(ctx):
    cfg = load_config()
    cfg.pop(str(ctx.guild.id), None)
    save_config(cfg)

    await ctx.send("🛑 Auto-scan dinonaktifkan.")

@bot.event
async def on_message(message):
    if message.author.bot:
        return

    # Tetap proses commands seperti !setchannel
    await bot.process_commands(message)

    if not message.guild or not message.attachments:
        return

    cfg = load_config()
    configured_channel = cfg.get(str(message.guild.id))

    if configured_channel != message.channel.id:
        return

    for attachment in message.attachments:
        if attachment.filename.lower().endswith(".lua"):
            await scan_attachment(message, attachment)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ Kamu tidak punya permission yang diperlukan.")
    elif isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.CommandInvokeError):
        print(repr(error.original))

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN belum diset di Railway Variables.")

bot.run(TOKEN)
