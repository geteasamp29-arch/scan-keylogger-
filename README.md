# SANZZLUA Bot – Deploy Guide (Railway)

## File di root repo (penting!)
```
SANZZLUA_bot.py
SANZZLUA_Scanner_bot.py
requirements.txt
runtime.txt
Procfile
railway.toml
```

## Langkah deploy

1. Push semua file di atas ke **root** GitHub repo (jangan taruh dalam folder lagi).

2. Railway → New Project → Deploy from GitHub repo.

3. **Variables** (Settings → Variables):
   ```
   DISCORD_BOT_TOKEN = isi_token_bot_kamu
   DISCORD_GUILD_ID  = isi_id_server (opsional)
   ```

4. **Settings → Deploy**:
   - Start Command: `python SANZZLUA_bot.py`
   - (Kalau mau Scanner): `python SANZZLUA_Scanner_bot.py`

5. Jangan isi **Build Command**. Biarkan kosong.

6. Redeploy.

## Kalau masih error
- Pastikan token tidak kosong / tidak ada spasi
- Pastikan file `.py` ada di root repo, bukan di subfolder
- Coba ganti Start Command jadi: `python3 SANZZLUA_bot.py`
