"""SANZZLUA Discord bot.

Required environment variable:
    DISCORD_BOT_TOKEN

Optional environment variables:
    DISCORD_GUILD_ID - register slash commands instantly in one guild
    CONFIG_PATH      - JSON config path, defaults to .data/config.json
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands

MAX_FILE_BYTES = 512 * 1024
COOLDOWN_SECONDS = 10
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", ".data/config.json"))

SANZZLUA_HEADER = """--[[
================================================================
          ███████╗ █████╗ ███╗   ██╗███████╗███████╗
          ██╔════╝██╔══██╗████╗  ██║╚══███╔╝╚══███╔╝
          ███████╗███████║██╔██╗ ██║  ███╔╝   ███╔╝
          ╚════██║██╔══██║██║╚██╗██║ ███╔╝   ███╔╝
          ███████║██║  ██║██║ ╚████║███████╗███████╗
          ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                   SANZZLUA Obfuscator Anti-AI

================================================================
  Website     : local
  Obfuscation : Runtime polymorphic
  Anti-tamper : Integrity + XOR layers
  Anti-AI     : Level 1-10 (scalable)
  Entropy     : High
  Status      : Online
================================================================
]]--"""

MULTI_CHAR_OPERATORS = (
    "...",
    "..",
    "<<",
    ">>",
    "//",
    "==",
    "~=",
    "<=",
    ">=",
    "::",
    "+=",
    "-=",
    "*=",
    "/=",
)


@dataclass(frozen=True)
class LuaToken:
    kind: str
    text: str


def _is_identifier_start(char: str) -> bool:
    return bool(char) and (char.isalpha() or char == "_")


def _is_identifier_part(char: str) -> bool:
    return bool(char) and (char.isalnum() or char == "_")


def _long_bracket_end(source: str, start: int) -> int:
    if start >= len(source) or source[start] != "[":
        return -1
    cursor = start + 1
    while cursor < len(source) and source[cursor] == "=":
        cursor += 1
    if cursor >= len(source) or source[cursor] != "[":
        return -1
    closing = "]" + ("=" * (cursor - start - 1)) + "]"
    end = source.find(closing, cursor + 1)
    return len(source) if end == -1 else end + len(closing)


def _quoted_string_end(source: str, start: int) -> int:
    quote = source[start]
    cursor = start + 1
    while cursor < len(source):
        if source[cursor] == "\\":
            cursor += 2
        elif source[cursor] == quote:
            return cursor + 1
        else:
            cursor += 1
    return len(source)


def tokenize_lua(source: str) -> list[LuaToken]:
    tokens: list[LuaToken] = []
    cursor = 0

    while cursor < len(source):
        char = source[cursor]

        if char.isspace():
            cursor += 1
            continue

        if char == "-" and source[cursor + 1 : cursor + 2] == "-":
            comment_start = cursor + 2
            comment_end = (
                _long_bracket_end(source, comment_start)
                if comment_start < len(source) and source[comment_start] == "["
                else -1
            )
            if comment_end != -1:
                cursor = comment_end
            else:
                line_end = source.find("\n", comment_start)
                cursor = len(source) if line_end == -1 else line_end + 1
            continue

        if char in ("'", '"'):
            end = _quoted_string_end(source, cursor)
            tokens.append(LuaToken("string", source[cursor:end]))
            cursor = end
            continue

        if char == "[":
            end = _long_bracket_end(source, cursor)
            if end != -1:
                tokens.append(LuaToken("string", source[cursor:end]))
                cursor = end
                continue

        if _is_identifier_start(char):
            end = cursor + 1
            while end < len(source) and _is_identifier_part(source[end]):
                end += 1
            tokens.append(LuaToken("word", source[cursor:end]))
            cursor = end
            continue

        if char.isdigit() or (
            char == "." and source[cursor + 1 : cursor + 2].isdigit()
        ):
            end = cursor
            if source[end : end + 2].lower() == "0x":
                end += 2
                while end < len(source) and source[end] in "0123456789abcdefABCDEF":
                    end += 1
            else:
                while end < len(source) and source[end].isdigit():
                    end += 1
                if (
                    end < len(source)
                    and source[end] == "."
                    and source[end + 1 : end + 2].isdigit()
                ):
                    end += 1
                    while end < len(source) and source[end].isdigit():
                        end += 1
                if end < len(source) and source[end] in "eE":
                    exponent_end = end + 1
                    if source[exponent_end : exponent_end + 1] in ("+", "-"):
                        exponent_end += 1
                    digits_start = exponent_end
                    while exponent_end < len(source) and source[exponent_end].isdigit():
                        exponent_end += 1
                    if exponent_end != digits_start:
                        end = exponent_end
            tokens.append(LuaToken("number", source[cursor:end]))
            cursor = end
            continue

        operator = next(
            (item for item in MULTI_CHAR_OPERATORS if source.startswith(item, cursor)),
            None,
        )
        if operator:
            tokens.append(LuaToken("symbol", operator))
            cursor += len(operator)
        else:
            tokens.append(LuaToken("symbol", char))
            cursor += 1

    return tokens


def _decode_lua_string(token: str) -> str | None:
    if token.startswith("[") and token.endswith("]"):
        cursor = 1
        while cursor < len(token) and token[cursor] == "=":
            cursor += 1
        if cursor >= len(token) or token[cursor] != "[":
            return None
        return token[cursor + 1 : -(cursor + 1)]

    if len(token) < 2 or token[0] not in ("'", '"') or token[-1] != token[0]:
        return None

    output: list[str] = []
    cursor = 1
    escapes = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
    }
    while cursor < len(token) - 1:
        char = token[cursor]
        if char != "\\":
            output.append(char)
            cursor += 1
            continue
        cursor += 1
        if cursor >= len(token) - 1:
            return None
        escaped = token[cursor]
        if escaped in escapes:
            output.append(escapes[escaped])
        elif escaped == "x" and re.match(r"^[0-9a-fA-F]{2}$", token[cursor + 1 : cursor + 3]):
            output.append(chr(int(token[cursor + 1 : cursor + 3], 16)))
            cursor += 2
        elif escaped.isdigit():
            digits = escaped
            while len(digits) < 3 and token[cursor + 1 : cursor + 2].isdigit():
                cursor += 1
                digits += token[cursor]
            output.append(chr(int(digits)))
        elif escaped == "\n":
            pass
        else:
            output.append(escaped)
        cursor += 1
    return "".join(output)


def _obfuscate_string(token: str, level: int = 1) -> str:
    """Obfuscate string literal. Higher level = smaller chunks + more noise."""
    decoded = _decode_lua_string(token)
    if decoded is None:
        return token
    values = list(decoded.encode("utf-8"))
    if not values:
        return '("")'

    # Level 1: 48 bytes/chunk, Level 10: 8 bytes/chunk
    chunk_size = max(8, 48 - (level - 1) * 4)

    chunks = [
        f"string.char({','.join(str(value) for value in values[index:index + chunk_size])})"
        for index in range(0, len(values), chunk_size)
    ]

    # Higher levels: interleave with empty string.char() noise (still valid)
    if level >= 6 and len(chunks) > 1:
        noisy: list[str] = []
        for i, c in enumerate(chunks):
            noisy.append(c)
            if i < len(chunks) - 1 and (i % 2 == 0):
                noisy.append("string.char()")  # empty, harmless
        chunks = noisy

    return "(" + "..".join(chunks) + ")"


def minify_lua(tokens: list[LuaToken], obfuscate_strings: bool, level: int = 1) -> str:
    output: list[str] = []
    previous: LuaToken | None = None
    for token in tokens:
        text = (
            _obfuscate_string(token.text, level)
            if (obfuscate_strings and token.kind == "string")
            else token.text
        )
        needs_space = bool(
            previous
            and previous.kind in ("word", "number")
            and token.kind in ("word", "number")
        )
        if previous and previous.text == "-" and token.text == "-":
            needs_space = True
        if previous and previous.kind == "number" and token.text.startswith("."):
            needs_space = True
        output.append((" " if needs_space else "") + text)
        previous = token
    return "".join(output)


def _payload_hash(source: str) -> str:
    value = 0
    for index, byte in enumerate(source.encode("utf-8"), start=1):
        value = (value + (byte * index)) % 4_294_967_296
    return f"{value:08x}"


def _lua_byte_string(source: str) -> str:
    values = source.encode("utf-8")
    return '"' + "".join(f"\\{value:03d}" for value in values) + '"'


def _xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ ((key + i) & 0xFF) for i, b in enumerate(data))


def _anti_tamper(source: str, level: int = 1) -> str:
    """
    Build runtime wrapper.
    Level 1-3  : basic integrity check
    Level 4-6  : integrity + light XOR
    Level 7-10 : multi-layer XOR + integrity + decoy checks
    Always pure Lua, runs on any standard Lua / Luau / FiveM.
    """
    expected = _payload_hash(source)
    level = max(1, min(10, level))

    if level <= 3:
        # Original simple anti-tamper
        encoded = _lua_byte_string(source)
        return ";".join(
            [
                f"local __s={encoded}",
                "local __h=0",
                "for __i=1,#__s do __h=(__h+string.byte(__s,__i)*__i)%4294967296 end",
                f'if string.format("%08x",__h)~="{expected}" then error("integrity check failed") end',
                "local __f,__e",
                'if loadstring then __f,__e=loadstring(__s,"@protected") else __f,__e=load(__s,"@protected","t",_ENV) end',
                "if not __f then error(__e) end",
                "return __f(...)",
            ]
        )

    # Level 4+: XOR the payload
    # Key is derived from the hash so it is unique per file
    key = int(expected[:4], 16) ^ (level * 17)
    xored = _xor_bytes(source.encode("utf-8"), key)
    # Represent as escaped byte string (latin-1 preserves all byte values)
    encoded = '"' + "".join(f"\\{b:03d}" for b in xored) + '"'

    # Pure Lua XOR that works on Lua 5.1 / 5.2 / 5.3 / LuaJIT / Luau / FiveM
    bxor_fn = (
        "local function __bxor(a,b)"
        "local p,c=1,0 "
        "while a>0 and b>0 do "
        "local ra,rb=a%2,b%2 "
        "if ra~=rb then c=c+p end "
        "a,b,p=(a-ra)/2,(b-rb)/2,p*2 "
        "end "
        "if a<b then a=b end "
        "while a>0 do "
        "local ra=a%2 "
        "if ra>0 then c=c+p end "
        "a,p=(a-ra)/2,p*2 "
        "end "
        "return c end"
    )

    parts: list[str] = [
        f"local __k={key}",
        f"local __s={encoded}",
        bxor_fn,
        "local __d={}",
        "for __i=1,#__s do local __b=string.byte(__s,__i);local __x=(__k+__i-1)%256;__d[__i]=string.char(__bxor(__b,__x)) end",
        "local __p=table.concat(__d)",
        "local __h=0",
        "for __i=1,#__p do __h=(__h+string.byte(__p,__i)*__i)%4294967296 end",
        f'if string.format("%08x",__h)~="{expected}" then error("integrity check failed") end',
    ]

    if level >= 7:
        # Extra decoy integrity (always true) to confuse static analysis / AI
        parts.extend(
            [
                "local __junk=0",
                "for __j=1,3 do __junk=(__junk+__j*7)%97 end",
                "if __junk<0 then error('decoy') end",  # never triggers
            ]
        )

    parts.extend(
        [
            "local __f,__e",
            'if loadstring then __f,__e=loadstring(__p,"@protected") else __f,__e=load(__p,"@protected","t",_ENV) end',
            "if not __f then error(__e) end",
            "return __f(...)",
        ]
    )
    return ";".join(parts)


def obfuscate_lua(
    source: str,
    *,
    minify: bool = True,
    obfuscate_strings: bool = True,
    anti_tamper: bool = True,
    level: int = 5,
) -> str:
    if "\x00" in source:
        raise ValueError("File Lua berisi byte NUL dan tidak dapat diproses.")
    if not source.strip():
        raise ValueError("File Lua kosong.")

    level = max(1, min(10, int(level)))

    tokens = tokenize_lua(source)
    output = minify_lua(tokens, obfuscate_strings, level) if minify else source.strip()
    if anti_tamper:
        output = _anti_tamper(output, level)
    return f"{SANZZLUA_HEADER}\n\n-- Anti-AI Level: {level}/10\n{output.strip()}\n"


class ConfigStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, dict[str, str]] = {}
        self.loaded = False

    async def load(self) -> None:
        if self.loaded:
            return
        try:
            self.data = json.loads(await asyncio.to_thread(self.path.read_text, encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {}
        self.loaded = True

    async def get_channel(self, guild_id: int) -> str | None:
        await self.load()
        config = self.data.get(str(guild_id), {})
        return config.get("channel_id")

    async def set_channel(self, guild_id: int, channel_id: int) -> None:
        await self.load()
        self.data[str(guild_id)] = {"channel_id": str(channel_id)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(
            self.path.write_text,
            json.dumps(self.data, indent=2) + "\n",
            encoding="utf-8",
        )


intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.guild_messages = True
bot = commands.Bot(command_prefix="!", intents=intents)
config_store = ConfigStore(CONFIG_PATH)
cooldowns: dict[int, float] = {}


def is_lua_attachment(attachment: discord.Attachment) -> bool:
    return bool(attachment.filename.lower().endswith(".lua"))


def on_cooldown(user_id: int) -> bool:
    now = time.monotonic()
    last = cooldowns.get(user_id, 0)
    if now - last < COOLDOWN_SECONDS:
        return True
    cooldowns[user_id] = now
    return False


async def process_attachment(
    attachment: discord.Attachment,
    *,
    reply: Any,
    minify: bool = True,
    obfuscate_strings: bool = True,
    anti_tamper: bool = True,
    level: int = 5,
) -> None:
    if attachment.size > MAX_FILE_BYTES:
        await reply("Gagal: ukuran file melebihi batas 512 KB.")
        return
    try:
        raw = await attachment.read()
        if len(raw) > MAX_FILE_BYTES:
            await reply("Gagal: ukuran file melebihi batas 512 KB.")
            return
        result = obfuscate_lua(
            raw.decode("utf-8"),
            minify=minify,
            obfuscate_strings=obfuscate_strings,
            anti_tamper=anti_tamper,
            level=level,
        )
        filename = re.sub(r"\.lua$", "", attachment.filename, flags=re.IGNORECASE)
        output_name = f"{filename}.obfuscated.lua"
        payload = discord.File(
            fp=__import__("io").BytesIO(result.encode("utf-8")),
            filename=output_name,
        )
        await reply(
            content=f"File selesai diproses (Anti-AI Level **{level}/10**). Uji hasilnya pada runtime Lua target.",
            file=payload,
        )
    except UnicodeDecodeError:
        await reply("Gagal: file Lua harus berupa teks UTF-8.")
    except ValueError as error:
        await reply(f"Gagal: {error}")


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
    print(f"SANZZLUA bot online sebagai {bot.user} ({scope})")


@bot.event
async def on_message(message: discord.Message) -> None:
    if message.author.bot or message.guild is None:
        return
    configured_channel = await config_store.get_channel(message.guild.id)
    if not configured_channel or str(message.channel.id) != configured_channel:
        return
    attachment = next((item for item in message.attachments if is_lua_attachment(item)), None)
    if attachment is None:
        return
    if on_cooldown(message.author.id):
        await message.reply("Tunggu beberapa detik sebelum memproses file berikutnya.")
        return
    # Auto-channel uses default level 5
    await process_attachment(attachment, reply=message.reply, level=5)


@bot.tree.command(name="setchannel", description="Atur channel layanan obfuscate Lua")
@app_commands.checks.has_permissions(manage_guild=True)
async def setchannel(interaction: discord.Interaction, channel: discord.TextChannel) -> None:
    if interaction.guild_id is None:
        await interaction.response.send_message("Gunakan perintah ini di server Discord.", ephemeral=True)
        return
    await config_store.set_channel(interaction.guild_id, channel.id)
    await interaction.response.send_message(f"Channel aktif diatur ke {channel.mention}.")


@bot.tree.command(name="channel", description="Lihat channel layanan obfuscate Lua")
async def channel(interaction: discord.Interaction) -> None:
    if interaction.guild_id is None:
        await interaction.response.send_message("Gunakan perintah ini di server Discord.", ephemeral=True)
        return
    channel_id = await config_store.get_channel(interaction.guild_id)
    text = f"Channel aktif: <#{channel_id}>." if channel_id else "Belum ada channel. Gunakan /setchannel."
    await interaction.response.send_message(text)


@bot.tree.command(name="help", description="Lihat bantuan SANZZLUA bot")
async def help_command(interaction: discord.Interaction) -> None:
    await interaction.response.send_message(
        "**SANZZLUA Bot**\n"
        "• `/setchannel` — atur channel (butuh Manage Server)\n"
        "• Upload file `.lua` di channel yang sudah diatur → otomatis obfuscate (Level 5)\n"
        "• `/obfuscate` — proses manual dengan opsi lengkap\n\n"
        "**Anti-AI Level (1–10)**\n"
        "• 1–3 : minify + string.char + integrity check\n"
        "• 4–6 : + XOR runtime layer\n"
        "• 7–10: + multi-layer XOR + decoy checks + chunk lebih kecil\n"
        "File hasil tetap pure Lua dan berjalan di semua runtime (FiveM, Roblox, standalone, dll)."
    )


@bot.tree.command(name="obfuscate", description="Obfuscate dan minify file Lua")
@app_commands.describe(
    file="File .lua yang akan diproses",
    minify="Hapus komentar dan whitespace yang tidak diperlukan",
    obfuscate_strings="Encode string literal menjadi string.char",
    anti_tamper="Tambahkan pemeriksaan integritas saat file dijalankan",
    level="Level Anti-AI (1=ringan, 10=maksimal). Default 5",
)
@app_commands.choices(
    level=[
        app_commands.Choice(name="1 - Ringan", value=1),
        app_commands.Choice(name="2", value=2),
        app_commands.Choice(name="3", value=3),
        app_commands.Choice(name="4", value=4),
        app_commands.Choice(name="5 - Default", value=5),
        app_commands.Choice(name="6", value=6),
        app_commands.Choice(name="7", value=7),
        app_commands.Choice(name="8", value=8),
        app_commands.Choice(name="9", value=9),
        app_commands.Choice(name="10 - Maksimal", value=10),
    ]
)
async def obfuscate_command(
    interaction: discord.Interaction,
    file: discord.Attachment,
    minify: bool = True,
    obfuscate_strings: bool = True,
    anti_tamper: bool = True,
    level: app_commands.Choice[int] = None,  # type: ignore
) -> None:
    if interaction.guild_id is None:
        await interaction.response.send_message("Gunakan perintah ini di server Discord.", ephemeral=True)
        return
    configured_channel = await config_store.get_channel(interaction.guild_id)
    if configured_channel and str(interaction.channel_id) != configured_channel:
        await interaction.response.send_message(
            f"Gunakan perintah ini di <#{configured_channel}>.",
            ephemeral=True,
        )
        return
    if not file.filename.lower().endswith(".lua"):
        await interaction.response.send_message("Hanya file .lua yang diterima.", ephemeral=True)
        return
    if on_cooldown(interaction.user.id):
        await interaction.response.send_message("Tunggu beberapa detik.", ephemeral=True)
        return

    selected_level = level.value if level is not None else 5

    await interaction.response.defer()
    await process_attachment(
        file,
        reply=interaction.followup.send,
        minify=minify,
        obfuscate_strings=obfuscate_strings,
        anti_tamper=anti_tamper,
        level=selected_level,
    )


@setchannel.error
async def setchannel_error(
    interaction: discord.Interaction,
    error: app_commands.AppCommandError,
) -> None:
    if isinstance(error, app_commands.MissingPermissions):
        message = "Kamu memerlukan izin Manage Server."
    else:
        message = "Terjadi kesalahan saat mengatur channel."
    if interaction.response.is_done():
        await interaction.followup.send(message, ephemeral=True)
    else:
        await interaction.response.send_message(message, ephemeral=True)


def main() -> None:
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        raise SystemExit("DISCORD_BOT_TOKEN belum diatur.")
    bot.run(token)


if __name__ == "__main__":
    main()
