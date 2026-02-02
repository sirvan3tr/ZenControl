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
-manifest     path to manifest file (default ./files.txt)
-key          encryption key (16/24/32 bytes); or set ZENCONTROL_KEY
-unlock-hour  local hour (0-23) after which decryption is allowed (default 19)
-pause        pause for Enter before exit
-allow-legacy allow legacy AES-CFB decrypt for older files
```

### Manifest:
The app reads a simple text manifest. Each non-empty line is:
```
filedir|filename|status
```
Example:
```
# filedir|filename|status
/Users/sev/Documents|notes.txt|decrypted
/Users/sev/Documents|report.pdf|encrypted
```
The app updates the `status` in this file after successful encrypt/decrypt.
You can start from `files.txt.example` and save it as `files.txt`.

### Notes:
- Encryption uses AES-GCM (authenticated). The encrypted file is base64 text with nonce+ciphertext.
- Use `-allow-legacy` to decrypt older AES-CFB encrypted files.
- Keys are required; there is no embedded default key. Use -key or ZENCONTROL_KEY.
- filedir should be a directory path; the app uses filepath.Join to build paths.

### Improvements needed:
- You can cheat it by chaning system clock and so on
- At the moment one has to add files to the local manifest by hand or with another program.
- Store key and manifest on a server that we don't have access to
- Get timestamp from trusted third party

ensure the forward or backward slash is included at the end of filedir
