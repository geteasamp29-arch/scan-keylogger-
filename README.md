# SANZZLUAONTOP Auto Scanner

Setelah `!setchannel`, cukup upload file `.lua` ke channel tersebut.
Tidak perlu mengetik `!scan`.

Commands:
- `!setchannel` = aktifkan auto-scan di channel saat ini
- `!disablechannel` = matikan auto-scan

Railway:
- Variable wajib: `DISCORD_TOKEN`
- Deploy sebagai worker dengan `python bot.py`

File Lua tidak pernah dieksekusi. Scanner melakukan static analysis dan decoding terbatas untuk Base64/hex.

Catatan: obfuscation arbitrer/VM/custom loader tidak dapat dijamin terdeteksi 100% oleh static scanner.
