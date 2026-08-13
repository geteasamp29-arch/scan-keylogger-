# SANZZLUA Bots

Dua bot Discord:

1. **SANZZLUA_bot.py** – Obfuscator Lua (Anti-AI Level 1–10)
2. **SANZZLUA_Scanner_bot.py** – Scanner WHEBOKS / keylogger / webhook

## Deploy di Railway (via GitHub)

### 1. Environment Variables (wajib)
```
DISCORD_BOT_TOKEN=token_bot_kamu
```

### 2. Optional
```
DISCORD_GUILD_ID=id_server_discord
```

### 3. Start Command (Railway)
Pilih salah satu:

**Obfuscator:**
```
python SANZZLUA_bot.py
```

**Scanner:**
```
python SANZZLUA_Scanner_bot.py
```

### 4. requirements.txt
Sudah disediakan. Railway akan install otomatis.

## Catatan
- Bot butuh intent: Message Content + Guilds
- Invite bot dengan scope `bot` + `applications.commands`
- Permission minimal: Send Messages, Attach Files, Use Slash Commands
