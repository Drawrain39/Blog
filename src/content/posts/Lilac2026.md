---
title: XCTF - LilacCTF 2026
featured: false
published: 2026-01-26
description: 第二次打XCTF分赛站，收获很多
tags: [CTF, Writeup, Reverse]
category: CTF
series: CTF Writeup
seriesOrder: 7
draft: false
---

写的不太完全，有两三道题解出来没写题解，无限期拖更了，第二次打这种大型赛事，wp写的也不是太好
# Reverse

## C\+\+\+\+ **\| SOLVED \| ing \- Drawrain**

flag核心校验函数在sub\_7FF600FAC6C0 函数

```C++
sub_7FF601074AB0(&off_7FF6011E17A0);
  sub_7FF601074FF0(10);
  sub_7FF601074B10(&off_7FF6011D7600);
  sub_7FF601074B10(&off_7FF6011D61E0);
  sub_7FF601074B10(&off_7FF6011D7600);
  sub_7FF601074B30(&off_7FF6011D6020);
  v0 = (_UNKNOWN **)sub_7FF601074AF0();
  if ( !v0 )
    v0 = &off_7FF6011D6008;
  result = sub_7FF600FB7650(v0, 3);
  v2 = result;
  if ( result && *(_DWORD *)(result + 8) )
  {
    v3 = sub_7FF600F33B40((unsigned __int16 *)&word_7FF601179950, 0x10u);
    *(_OWORD *)(v3 + 16) = xmmword_7FF601129460;
    v4 = sub_7FF600FAC850(v3, 65);
    v5 = sub_7FF600F33B40((unsigned __int16 *)&word_7FF601179950, 0x10u);
    *(_OWORD *)(v5 + 16) = xmmword_7FF601129450;
    v6 = sub_7FF600FAC850(v5, 49);
    v7 = sub_7FF600F33A20((__int64)&unk_7FF601139038);
    sub_7FF600FAC490(v7, v4, v6);
    v8 = sub_7FF600F31A9E();
    v9 = (*(__int64 (__fastcall **)(_QWORD, __int64))(**(_QWORD **)(v8 + 8) + 112LL))(*(_QWORD *)(v8 + 8), v2);
    v10 = sub_7FF600FAC4E0(v7, v9);
    v11 = sub_7FF600FBDD10(v10);
    v12 = sub_7FF600FB6530(v11, &off_7FF6011D6DE8, &off_7FF6011D6008);
    if ( (unsigned int)sub_7FF600FB40D0(v12, &off_7FF6011D7738) )
    {
      sub_7FF601074FF0(11);
      sub_7FF601074B10(&off_7FF6011D60E0);
    }
    else
    {
      sub_7FF601074FF0(12);
      sub_7FF601074B10(&off_7FF6011D6068);
    }
    return sub_7FF601075060();
  }
  return result;
}
```

在7FF600FAC890打断点，动调sub\_7FF600FAC4E0

经历过异或得到实际上的key:WONDERFUL\&\&PEACE  在我动调过程中发现这个iv似乎没有用到

iv实际上为somedanctoforget~~（到最后也没用到）~~

密文比对，提取off\_7FF6011D7738

```C++
0x40,0x0,0x0,0x0,0x41,0x0,0x32,0x0,0x30,0x0,0x34,0x0,0x39,0x0,0x32,0x0,0x31,0x0,0x35,0x0,0x32,0x0,0x37,0x0,0x33,0x0,0x35,0x0,0x42,0x0,0x34,0x0,0x46,0x0,0x36,0x0,0x45,0x0,0x43,0x0,0x42,0x0,0x41,0x0,0x41,0x0,0x33,0x0,0x35,0x0,0x39,0x0,0x44,0x0,0x42,0x0,0x36,0x0,0x34,0x0,0x34,0x0,0x31,0x0,0x37,0x0,0x42,0x0,0x44,0x0,0x46,0x0,0x32,0x0,0x37,0x0,0x37,0x0,0x41,0x0,0x37,0x0,0x33,0x0,0x42,0x0,0x30,0x0,0x38,0x0,0x35,0x0,0x36,0x0,0x36,0x0,0x36,0x0,0x30,0x0,0x33,0x0,0x34,0x0,0x43,0x0,0x46,0x0,0x33,0x0,0x38,0x0,0x45,0x0,0x37,0x0,0x34,0x0,0x38,0x0,0x44,0x0,0x38,0x0,0x46,0x0,0x42,0x0,0x44,0x0,0x34,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
```

去掉0x40 0x0 0x0 0x0

实际上的密文为A20492152735B4F6ECBAA359DB64417BDF277A73B085666034CF38E748D8FBD4

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=NDU0MmM2MzhkZDU0ZjE5MDc1MWIwNDU5OTUzZmRkNmFfMzQyMmRhNWNkYzM1YjMxNTk0ZmYwY2QyZmI4MzY5NDJfSUQ6NzcwNTgxOTYxNjA1NjE2NzQxOV8xNzk0MTUxMDU0OjE3OTQyMzc0NTRfVjM)

有AES的S盒，标准无魔改

最终确定是twofish旋转常数魔改，twofish\+AES\-s\-box的拼装

```C++
void __fastcall sub_14007CA40(unsigned int *a1, __int64 a2, __int64 a3)
{
  int i; // ecx
  int j; // ebp
  int v7; // r12d
  int v8; // eax
  int v9; // eax
  int v10; // eax
  int k; // eax
  __int64 v12; // [rsp+28h] [rbp-50h]
  __int64 v13; // [rsp+30h] [rbp-48h]
  __int64 __security_cookie; // [rsp+38h] [rbp-40h]

  v12 = 0;
  v13 = 0;
  for ( i = 0; i < 4; ++i )
    *((_DWORD *)&v12 + i) = a1[i + 4] ^ *(_DWORD *)(a2 + 4LL * i);
  for ( j = 0; j < 16; ++j )
  {
    v7 = sub_14007CC20(a1, v12, 0);
    v8 = sub_14007CC20(a1, __ROL4__(HIDWORD(v12), 8), 0);
    HIDWORD(v13) = __ROL4__(HIDWORD(v13), 5);
    LODWORD(v13) = (a1[2 * j + 12] + v7 + v8) ^ v13;
    HIDWORD(v13) ^= a1[2 * j + 13] + v7 + 2 * v8;
    LODWORD(v13) = __ROL4__(v13, 27);
    if ( j < 15 )
    {
      v9 = v12;
      LODWORD(v12) = v13;
      LODWORD(v13) = v9;
      v10 = HIDWORD(v12);
      HIDWORD(v12) = HIDWORD(v13);
      HIDWORD(v13) = v10;
    }
  }
  for ( k = 0; k < 4; ++k )
    *(_DWORD *)(a3 + 4LL * k) = a1[k + 8] ^ *((_DWORD *)&v12 + k);
  if ( __security_cookie != _security_cookie )
    cexit_0();
}
```

这里是魔改twofish的轮旋转

最终exp:

```Python
cip = "A20492152735B4F6ECBAA359DB64417BDF277A73B085666034CF38E748D8FBD4"
key = b"WONDERFUL&&PEACE" 
mask32 = 0xFFFFFFFF
def rol32(x, n):
    x &= mask32
    n &= 31
    return ((x << n) | (x >> (32 - n))) & mask32

sbox = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
inv = [0]*256
for i,v in enumerate(sbox):
    inv[v] = i

def d4e0(x, poly=0x11b):
    x &= 0xFF
    a = (x >> 2) & 0xFF
    if x & 2:
        a ^= (poly >> 1) & 0xFF
    if x & 1:
        a ^= (poly >> 2) & 0xFF
    return a & 0xFF

def build_mds():
    m0=[0]*256; m1=[0]*256; m2=[0]*256; m3=[0]*256
    for i in range(256):
        y = sbox[i]
        r12 = d4e0(y) ^ y
        r13 = (y >> 1) & 0xFF
        r14 = 0x8d if (y & 1) else 0
        tmp = d4e0(y)
        r13 ^= y
        r14 ^= r13
        r14 ^= tmp
        r14 &= 0xFF

        w0 = (r12) | (y<<8) | (r14<<16) | (y<<24)
        w1 = (y) | (r14<<8) | (r12<<16) | (r14<<24)
        w2 = (r14) | (r12<<8) | (y<<16) | (r12<<24)
        w3 = w0

        m0[i]=w0 & mask32
        m1[i]=w1 & mask32
        m2[i]=w2 & mask32
        m3[i]=w3 & mask32
    return m0,m1,m2,m3

M0,M1,M2,M3 = build_mds()

def rs_mul2(b):
    b &= 0xFF
    r = (b << 1) & 0x1FF
    if b & 0x80:
        r ^= 0x11d
    return r & 0xFF

def rs_div2(b):
    b &= 0xFF
    r = (b >> 1) & 0x7F
    if b & 1:
        r ^= 0x8e
    return r & 0xFF

def RS_rem(x):
    x &= mask32
    b = (x >> 24) & 0xFF
    g2 = rs_mul2(b)
    g3 = rs_div2(b) ^ g2
    b0 = (x & 0xFF) ^ g3
    b1 = ((x >> 8) & 0xFF) ^ g2
    b2 = ((x >> 16) & 0xFF) ^ g3
    b3 = b
    return ((b3<<24)|(b2<<16)|(b1<<8)|b0) & mask32

def RS_MDS_Encode(k0, k1):
    r = 0
    for w in (k1, k0):        
        r ^= (w & mask32)
        for _ in range(4):
            r = RS_rem(r)
    return r & mask32
#这里只走k = 2 
def h_func(x, L0, L1):
    x &= mask32; L0 &= mask32; L1 &= mask32
    b0 = x & 0xFF
    b1 = (x >> 8) & 0xFF
    b2 = (x >> 16) & 0xFF
    b3 = (x >> 24) & 0xFF

    t0 = sbox[b0]
    t0 = inv[t0 ^ (L1 & 0xFF)]
    t0 ^= (L0 & 0xFF)
    y = M0[t0]

    t1 = inv[b1]
    t1 = inv[t1 ^ ((L1 >> 8) & 0xFF)]
    t1 ^= ((L0 >> 8) & 0xFF)
    y ^= M1[t1]

    t2 = sbox[b2]
    t2 = sbox[t2 ^ ((L1 >> 16) & 0xFF)]
    t2 ^= ((L0 >> 16) & 0xFF)
    y ^= M2[t2]

    t3 = inv[b3]
    t3 = sbox[t3 ^ ((L1 >> 24) & 0xFF)]
    t3 ^= ((L0 >> 24) & 0xFF)
    y ^= M3[t3]

    return y & mask32

def key_schedule(key_bytes):
    words = [int.from_bytes(key_bytes[i:i+4], "little") for i in range(0,16,4)]
    Me = [words[0], words[2]]
    Mo = [words[1], words[3]]

    S = [0,0]
    for i in range(2):
        S[1-i] = RS_MDS_Encode(Me[i], Mo[i])

    step = 0x0A0A0A0A
    off  = 0x0D0D0D0D
    rot  = 13

    K = [0]*40
    for i in range(20):
        a_in = (step*i) & mask32
        b_in = (a_in + off) & mask32
        A = h_func(a_in, Me[0], Me[1])
        B = rol32(h_func(b_in, Mo[0], Mo[1]), 8)
        K[2*i]   = (A + B) & mask32
        K[2*i+1] = rol32((A + (2*B & mask32)) & mask32, rot)

    return S, K

def block_decrypt(block16, S, K):
    w = [int.from_bytes(block16[i:i+4], "little") for i in range(0,16,4)]
    R = [(w[i] ^ K[i+4]) & mask32 for i in range(4)]
    S0,S1 = S

    for r in range(15, -1, -1):
        if r < 15:
            R[0],R[2] = R[2],R[0]
            R[1],R[3] = R[3],R[1]

        t0 = h_func(R[0], S0, S1)
        t1 = h_func(rol32(R[1], 8), S0, S1)

        R[2] = rol32(R[2], 5)
        F0 = (t0 + t1 + K[8+2*r]) & mask32
        R[2] ^= F0

        F1 = (t0 + (2*t1 & mask32) + K[9+2*r]) & mask32
        R[3] ^= F1
        R[3] = rol32(R[3], 27)

    P = [(R[i] ^ K[i]) & mask32 for i in range(4)]
    return b"".join(x.to_bytes(4, "little") for x in P)

def main():
    S,K = key_schedule(key)
    ct = bytes.fromhex(cip)
    pt = b"".join(block_decrypt(ct[i:i+16], S, K) for i in range(0, len(ct), 16))
    pt = pt.rstrip(b"\x00")
    print(pt.decode())

if __name__ == "__main__":
    main()
```

LilacCTF\{I\_ju3t\_w@nnA\_b3\_hapPy\}



## ezPython **\| SOLVED \| ing \- Drawrain**

> python版本需要相同3\.9，不然这个PYZ\-00\.pyz\_extracted是空的很麻烦\.\.\.\.\.（后续Azusaq学长说可以注释掉pyinstxtractor\.py的版本校验，确实省去了这个麻烦）
> 
> 

反编译回py，同时需要myalgo\.py

```Python
import struct
from crypto import *
from sys import *
import base64
import myalgo
welcome_msg = 'V2VsYzBtMyBUbyBUaGUgV29ybGQgb2YgTDFsYWMgPDM='
input_msg = ':i(G#8T&KiF<F_)F`JToCggs;'
right_msg = 'UmlnaHQsIGNvbmdyYXR1bGF0aW9ucyE='
wrong_msg = 'V3JvbmcgRmxhZyE='
print(b64decode(welcome_msg).decode())
flag = input(a85decode(input_msg).decode())
if not (flag.startswith('LilacCTF{') and flag.endswith('}') and (len(flag) == 26)):
    print(b64decode(wrong_msg).decode())
else:
    flag = flag[9:25]
    res = [761104570, 1033127419, 3729026053, 795718415]
    key = struct.unpack('<IIII', b'1111222233334444')
    input = list(struct.unpack('<IIII', flag.encode()))
    myalgo.btea(input, 4, key)
    if input[0] == res[0] and input[1] == res[1] and (input[2] == res[2]) and (input[3] == res[3]):
        print(b64decode(right_msg).decode())
    else:
        print(b64decode(wrong_msg).decode())
```

取中间16个字节校验

存在

```C++
flag = input(a85decode(input_msg).decode())
```

patch之后MX会变，同时btea算法DELTA = 0x45555254，有魔改

最终exp:

```Python
import struct

res = [761104570, 1033127419, 3729026053, 795718415]
key = list(struct.unpack("<IIII", b"1111222233334444"))
DELTA = struct.unpack("<I", b"TRUE")[0]  #0x45555254

def u32(x): 
    return x & 0xffffffff

def MX(y, z, s, k, p, e):
    return (((z << 3) ^ (y >> 5)) + ((y << 4) ^ (z >> 2))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))

def btea_decrypt(v, n, k):
    rounds = 6 + 52 // n
    s = u32(rounds * DELTA)
    y = v[0]
    while s != 0:
        e = u32(s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = u32(v[p] - MX(y, z, s, k, p, e))
            y = v[p]
        z = v[n - 1]
        v[0] = u32(v[0] - MX(y, z, s, k, 0, e))
        y = v[0]
        s = u32(s - DELTA)
    return v

pt_words = btea_decrypt(res.copy(), 4, key)
mid = struct.pack("<IIII", *pt_words).decode()
flag = f"LilacCTF{{{mid}}}"
print(flag)
#LilacCTF{e@sy_Pyth0n_SMC!}
```

LilacCTF\{e@sy\_Pyth0n\_SMC\!\}
