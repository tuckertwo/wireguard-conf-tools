#!/usr/bin/env python3

from sys import stdin
import json5
import nacl.utils
import nacl.public

b64 = nacl.encoding.Base64Encoder

config = json5.loads(stdin.buffer.read())

# Do stuff here
for i in config:
    if not "priv_key" in i:
        priv_key = nacl.public.PrivateKey.generate()
        i["priv_key"] = priv_key.encode(b64).decode("utf-8")
    if not "publ_key" in i:
        priv_key = nacl.public.PrivateKey(bytes(i["priv_key"], "utf-8"), b64)
        i["publ_key"] = priv_key.public_key.encode(b64).decode("utf-8")

print(json5.dumps(config))
