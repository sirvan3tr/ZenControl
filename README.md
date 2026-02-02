# ZenControl
Helps productivity by encrypting files and programs and only decrypt after a certain time of the day. I have set this time to 1900.

### Build:
```
go build -o ZenControl ./src/ZenControl.go
```

### To Encrypt:
```
ZENCONTROL_KEY="your-32-byte-key-here" ./ZenControl encrypt
```

### To decrypt:
```
ZENCONTROL_KEY="your-32-byte-key-here" ./ZenControl decrypt
```

### Flags:
```
-db           path to sqlite database (default ./files.db)
-key          encryption key (16/24/32 bytes); or set ZENCONTROL_KEY
-unlock-hour  local hour (0-23) after which decryption is allowed (default 19)
-pause        pause for Enter before exit
-allow-legacy allow legacy AES-CFB decrypt for older files
```

### Database:
id, filename, filedir, status

### Notes:
- Encryption uses AES-GCM (authenticated). The encrypted file is base64 text with nonce+ciphertext.
- Use `-allow-legacy` to decrypt older AES-CFB encrypted files.
- Keys are required; there is no embedded default key. Use -key or ZENCONTROL_KEY.
- filedir should be a directory path; the app uses filepath.Join to build paths.

### Improvements needed:
- You can cheat it by chaning system clock and so on
- At the moment one has to add files to the local, files.db, database by having another programme add it for you.
- Store key and db on a server that we don't have access to
- Get timestamp from trusted third party

ensure the forward or backward slash is included at the end of filedir

Thanks
Sirvan
