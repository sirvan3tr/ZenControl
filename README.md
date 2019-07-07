# ZenControl
Helps productivity by encrypting files and programs and only decrypt after a certain time of the day. I have set this time to 1900.

### To Encrypt:
```
./ZenControl encrypt
```

### To decrypt:
```
./ZenControl decrypt
```

### Database:
id, filename, filedir, status

### Improvements needed:
- You can cheat it by chaning system clock and so on
- At the moment one has to add files to the local, files.db, database by having another programme add it for you.
- Store key and db on a server that we don't have access to
- Get timestamp from trusted third party

ensure the forward or backward slash is included at the end of filedir

Thanks
Sirvan