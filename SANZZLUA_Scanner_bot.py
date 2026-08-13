"""SANZZLUA Scanner Bot – deteksi WHEBOKS / keylogger / webhook berbahaya
bahkan pada file Lua yang sudah di-obfuscate kuat.

Required:
    DISCORD_BOT_TOKEN

Optional:
    DISCORD_GUILD_ID
    CONFIG_PATH
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import discord
from discord import app_commands
from discord.ext import commands

MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB
COOLDOWN_SECONDS = 8
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", ".data/scanner_config.json"))

# ---------------------------------------------------------------------------
# Signature database (defensive)
# ---------------------------------------------------------------------------

# Kata kunci yang dianggap sangat mencurigakan
CRITICAL_KEYWORDS = [
    r"wheboks",
    r"whebox",
    r"keylogger",
    r"keylog",
    r"keystroke",
    r"getasynckeystate",
    r"setwindowshookex",
    r"wh_keyboard_ll",
    r"getkeyboardstate",
    r"mapvirtualkey",
    r"toascii",
    r"sendinput",
    r"token.?logger",
    r"discord.?token",
    r"steal.?token",
    r"grab.?token",
    r"webhook.?logger",
]

# Pola URL / webhook
URL_PATTERNS = [
    re.compile(r"https?://[^\s\"'`<>\]\)]+", re.I),
    re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+", re.I),
    re.compile(r"discord\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+", re.I),
]

# Domain / host yang sering dipakai exfil (bisa ditambah)
SUSPICIOUS_HOSTS = [
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "pastebin.com",
    "hastebin.com",
    "ghostbin",
    "rentry.co",
    "raw.githubusercontent.com",
]

# Pola Lua yang sering muncul di malware / loader
LUA_SUSPICIOUS = [
    r"loadstring\s*\(",
    r"load\s*\(",
    r"RunString",
    r"CompileString",
    r"http\.Fetch",
    r"http\.Post",
    r"PerformHttpRequest",
    r"HttpGet",
    r"game\.HttpGet",
    r"syn\.request",
    r"request\s*\(",
    r"fluxus\.request",
    r"getgenv",
    r"getfenv",
    r"setfenv",
    r"debug\.getinfo",
    r"string\.dump",
]

# Pola string.char yang bisa di-decode
STRING_CHAR_RE = re.compile(
    r"string\.char\s*\(\s*((?:\d+\s*,?\s*)+)\)",
    re.I,
)

# Pola byte escaped "\065\066..."
ESCAPED_BYTES_RE = re.compile(r"(?:\\[0-9]{1,3}){4,}")

# Pola XOR sederhana dari obfuscator sebelumnya
XOR_HINT_RE = re.compile(r"__bxor|__k\s*=\s*\d+|integrity check failed", re.I)


@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / MEDIUM / INFO
    category: str
    detail: str
    evidence: str = ""


@dataclass
class ScanResult:
    filename: str
    size: int
    findings: list[Finding] = field(default_factory=list)
    decoded_snippets: list[str] = field(default_factory=list)
    raw_urls: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "INFO": 1}
        return sum(weights.get(f.severity, 0) for f in self.findings)

    @property
    def verdict(self) -> str:
        s = self.score
        if s >= 60:
            return "🔴 SANGAT BERBAHAYA"
        if s >= 30:
            return "🟠 BERBAHAYA"
        if s >= 12:
            return "🟡 MENCURIGAKAN"
        if s > 0:
            return "🔵 ADA TEMUAN RINGAN"
        return "🟢 BERSIH (tidak ditemukan signature)"


# ---------------------------------------------------------------------------
# De-obfuscation helpers (light, safe, no execution)
# ---------------------------------------------------------------------------

def decode_string_char(text: str) -> list[str]:
    """Extract and decode string.char(65,66,67) sequences."""
    results = []
    for m in STRING_CHAR_RE.finditer(text):
        nums = re.findall(r"\d+", m.group(1))
        try:
            chars = "".join(chr(int(n) % 256) for n in nums if 0 <= int(n) <= 255)
            if chars.strip() and len(chars) >= 3:
                results.append(chars)
        except Exception:
            continue
    return results


def decode_escaped_bytes(text: str) -> list[str]:
    """Decode sequences like \\065\\066\\067."""
    results = []
    for m in ESCAPED_BYTES_RE.finditer(text):
        raw = m.group(0)
        parts = re.findall(r"\\([0-9]{1,3})", raw)
        try:
            chars = "".join(chr(int(p) % 256) for p in parts if 0 <= int(p) <= 255)
            if chars.strip() and len(chars) >= 4:
                results.append(chars)
        except Exception:
            continue
    return results


def extract_all_strings(text: str) -> str:
    """Combine original text + decoded layers for scanning."""
    layers = [text]
    layers.extend(decode_string_char(text))
    layers.extend(decode_escaped_bytes(text))

    # second pass on already decoded content
    extra = []
    for layer in layers[1:]:
        extra.extend(decode_string_char(layer))
        extra.extend(decode_escaped_bytes(layer))
    layers.extend(extra)

    return "\n".join(layers)


def extract_urls(text: str) -> list[str]:
    found = set()
    for pat in URL_PATTERNS:
        for m in pat.finditer(text):
            url = m.group(0).rstrip(".,;)]}>'\"")
            if len(url) > 10:
                found.add(url)
    return sorted(found)


# ---------------------------------------------------------------------------
# Scanner core
# ---------------------------------------------------------------------------

def scan_content(filename: str, raw: bytes) -> ScanResult:
    result = ScanResult(filename=filename, size=len(raw))

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    combined = extract_all_strings(text)
    lower = combined.lower()

    # 1. Critical keywords (including WHEBOKS)
    for kw in CRITICAL_KEYWORDS:
        for m in re.finditer(kw, lower, re.I):
            start = max(0, m.start() - 40)
            end = min(len(combined), m.end() + 40)
            evidence = combined[start:end].replace("\n", " ")
            sev = "CRITICAL" if "wheboks" in kw or "keylog" in kw else "HIGH"
            result.findings.append(
                Finding(
                    severity=sev,
                    category="Keyword",
                    detail=f"Ditemukan pola: `{m.group(0)}`",
                    evidence=evidence[:120],
                )
            )

    # 2. URLs
    urls = extract_urls(combined)
    result.raw_urls = urls
    for url in urls:
        host = urlparse(url).netloc.lower()
        path = urlparse(url).path.lower()
        full = url.lower()

        if "wheboks" in full or "whebox" in full:
            result.findings.append(
                Finding(
                    severity="CRITICAL",
                    category="URL / WHEBOKS",
                    detail=f"URL mengandung WHEBOKS: `{url[:100]}`",
                    evidence=url[:150],
                )
            )
        elif "webhook" in full:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    category="Discord Webhook",
                    detail=f"Discord webhook terdeteksi: `{url[:90]}...`",
                    evidence=url[:150],
                )
            )
        elif any(s in full for s in SUSPICIOUS_HOSTS):
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    category="Suspicious Host",
                    detail=f"Host mencurigakan: `{host}`",
                    evidence=url[:120],
                )
            )
        else:
            result.findings.append(
                Finding(
                    severity="INFO",
                    category="URL",
                    detail=f"URL ditemukan: `{url[:80]}`",
                    evidence=url[:100],
                )
            )

    # 3. Lua suspicious APIs
    for pat in LUA_SUSPICIOUS:
        if re.search(pat, text, re.I):
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    category="Lua API",
                    detail=f"Pola API mencurigakan: `{pat}`",
                )
            )

    # 4. Obfuscation indicators (info only)
    if STRING_CHAR_RE.search(text) or ESCAPED_BYTES_RE.search(text):
        result.findings.append(
            Finding(
                severity="INFO",
                category="Obfuscation",
                detail="Terdeteksi teknik string.char / escaped bytes (umum di obfuscator)",
            )
        )
    if XOR_HINT_RE.search(text):
        result.findings.append(
            Finding(
                severity="INFO",
                category="Obfuscation",
                detail="Terdeteksi indikasi XOR / anti-tamper wrapper",
            )
        )

    # Keep unique findings (by detail)
    seen = set()
    unique = []
    for f in result.findings:
        key = (f.severity, f.detail)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    result.findings = unique

    # Save some decoded snippets for the report
    decoded = decode_string_char(text) + decode_escaped_bytes(text)
    result.decoded_snippets = [s[:200] for s in decoded if len(s) > 5][:8]

    return result


def format_report(result: ScanResult) -> str:
    lines = [
        f"**📄 File:** `{result.filename}` ({result.size:,} bytes)",
        f"**Verdict:** {result.verdict}",
        f"**Score:** `{result.score}`",
        "",
    ]

    if not result.findings:
        lines.append("Tidak ada signature berbahaya yang cocok.")
        return "\n".join(lines)

    # Group by severity
    order = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    for sev in order:
        group = [f for f in result.findings if f.severity == sev]
        if not group:
            continue
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "🔵"}[sev]
        lines.append(f"**{emoji} {sev}** ({len(group)})")
        for f in group[:12]:  # limit
            lines.append(f"• **{f.category}** — {f.detail}")
            if f.evidence:
                lines.append(f"  └ `{f.evidence[:100]}`")
        lines.append("")

    if result.decoded_snippets:
        lines.append("**🧩 Cuplikan yang berhasil di-decode:**")
        for s in result.decoded_snippets[:5]:
            safe = s.replace("`", "'")[:90]
            lines.append(f"• `{safe}`")
        lines.append("")

    if result.raw_urls:
        lines.append(f"**🔗 Total URL ditemukan:** {len(result.raw_urls)}")

    return "\n".join(lines)[:1900]  # Discord limit safety


# ---------------------------------------------------------------------------
# Discord bot
# ---------------------------------------------------------------------------

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.guild_messages = True
bot = commands.Bot(command_prefix="!", intents=intents)
cooldowns: dict[int, float] = {}


class ConfigStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, dict[str, str]] = {}
        self.loaded = False

    async def load(self) -> None:
        if self.loaded:
            return
        try:
            self.data = json.loads(
                await asyncio.to_thread(self.path.read_text, encoding="utf-8")
            )
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {}
        self.loaded = True

    async def get_channel(self, guild_id: int) -> str | None:
        await self.load()
        return self.data.get(str(guild_id), {}).get("channel_id")

    async def set_channel(self, guild_id: int, channel_id: int) -> None:
        await self.load()
        self.data[str(guild_id)] = {"channel_id": str(channel_id)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(
            self.path.write_text,
            json.dumps(self.data, indent=2) + "\n",
            encoding="utf-8",
        )


config_store = ConfigStore(CONFIG_PATH)


def on_cooldown(user_id: int) -> bool:
    now = time.monotonic()
    last = cooldowns.get(user_id, 0)
    if now - last < COOLDOWN_SECONDS:
        return True
    cooldowns[user_id] = now
    return False


ALLOWED_EXT = {".lua", ".txt", ".js", ".py", ".luac", ".vbs", ".ps1", ".bat"}


def is_scannable(attachment: discord.Attachment) -> bool:
    name = attachment.filename.lower()
    return any(name.endswith(ext) for ext in ALLOWED_EXT) or attachment.size < 50_000


async def process_scan(
    attachment: discord.Attachment,
    *,
    reply: Any,
) -> None:
    if attachment.size > MAX_FILE_BYTES:
        await reply("Gagal: file terlalu besar (max 1 MB).")
        return
    try:
        raw = await attachment.read()
        result = scan_content(attachment.filename, raw)
        report = format_report(result)

        # Color based on verdict
        if result.score >= 60:
            color = discord.Color.dark_red()
        elif result.score >= 30:
            color = discord.Color.red()
        elif result.score >= 12:
            color = discord.Color.orange()
        elif result.score > 0:
            color = discord.Color.blue()
        else:
            color = discord.Color.green()

        embed = discord.Embed(
            title="SANZZLUA Scanner",
            description=report,
            color=color,
        )
        embed.set_footer(text="Scan statis • tidak mengeksekusi file")
        await reply(embed=embed)
    except Exception as e:
        await reply(f"Gagal scan: `{e}`")


@bot.event
async def on_ready() -> None:
    guild_id = os.getenv("DISCORD_GUILD_ID")
    if guild_id:
        guild = discord.Object(id=int(guild_id))
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
        scope = f"guild {guild_id}"
    else:
        await bot.tree.sync()
        scope = "global"
    print(f"SANZZLUA Scanner online sebagai {bot.user} ({scope})")


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.author.bot or message.guild is None:
        return
    configured = await config_store.get_channel(message.guild.id)
    if not configured or str(message.channel.id) != configured:
        return
    attachment = next(
        (a for a in message.attachments if is_scannable(a)), None
    )
    if attachment is None:
        return
    if on_cooldown(message.author.id):
        await message.reply("Tunggu beberapa detik sebelum scan berikutnya.")
        return
    await process_scan(attachment, reply=message.reply)


@bot.tree.command(name="setchannel", description="Atur channel scan otomatis")
@app_commands.checks.has_permissions(manage_guild=True)
async def setchannel(
    interaction: discord.Interaction, channel: discord.TextChannel
) -> None:
    if interaction.guild_id is None:
        await interaction.response.send_message(
            "Gunakan di server Discord.", ephemeral=True
        )
        return
    await config_store.set_channel(interaction.guild_id, channel.id)
    await interaction.response.send_message(
        f"Channel scan diatur ke {channel.mention}."
    )


@bot.tree.command(name="channel", description="Lihat channel scan aktif")
async def channel_cmd(interaction: discord.Interaction) -> None:
    if interaction.guild_id is None:
        await interaction.response.send_message(
            "Gunakan di server Discord.", ephemeral=True
        )
        return
    cid = await config_store.get_channel(interaction.guild_id)
    text = (
        f"Channel aktif: <#{cid}>."
        if cid
        else "Belum ada channel. Gunakan /setchannel."
    )
    await interaction.response.send_message(text)


@bot.tree.command(name="scan", description="Scan file untuk WHEBOKS / keylogger / webhook")
@app_commands.describe(file="File yang akan di-scan (.lua, .txt, .js, dll)")
async def scan_command(
    interaction: discord.Interaction, file: discord.Attachment
) -> None:
    if interaction.guild_id is None:
        await interaction.response.send_message(
            "Gunakan di server Discord.", ephemeral=True
        )
        return
    if on_cooldown(interaction.user.id):
        await interaction.response.send_message(
            "Tunggu beberapa detik.", ephemeral=True
        )
        return
    if not is_scannable(file):
        await interaction.response.send_message(
            "Tipe file tidak didukung.", ephemeral=True
        )
        return
    await interaction.response.defer()
    await process_scan(file, reply=interaction.followup.send)


@bot.tree.command(name="help", description="Bantuan SANZZLUA Scanner")
async def help_command(interaction: discord.Interaction) -> None:
    await interaction.response.send_message(
        "**SANZZLUA Scanner**\n"
        "Bot ini mendeteksi indikasi **WHEBOKS**, **keylogger**, **Discord webhook**, "
        "dan pola berbahaya lain — termasuk di file yang sudah di-obfuscate.\n\n"
        "**Cara pakai:**\n"
        "• `/setchannel` — set channel auto-scan (butuh Manage Server)\n"
        "• Upload file di channel tersebut → otomatis di-scan\n"
        "• `/scan` — scan manual file\n\n"
        "**Yang dideteksi:**\n"
        "• Keyword `WHEBOKS` / `keylogger` / token stealer\n"
        "• Discord webhook URL\n"
        "• `GetAsyncKeyState`, `SetWindowsHookEx`, dll\n"
        "• `string.char(...)` & escaped bytes (di-decode dulu baru di-scan)\n"
        "• Pola loadstring + HTTP exfil\n\n"
        "⚠️ Scan bersifat **statis** — tidak mengeksekusi file."
    )


@setchannel.error
async def setchannel_error(
    interaction: discord.Interaction, error: app_commands.AppCommandError
) -> None:
    msg = (
        "Butuh izin Manage Server."
        if isinstance(error, app_commands.MissingPermissions)
        else "Terjadi kesalahan."
    )
    if interaction.response.is_done():
        await interaction.followup.send(msg, ephemeral=True)
    else:
        await interaction.response.send_message(msg, ephemeral=True)


def main() -> None:
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        raise SystemExit("DISCORD_BOT_TOKEN belum diatur.")
    bot.run(token)


if __name__ == "__main__":
    main()
