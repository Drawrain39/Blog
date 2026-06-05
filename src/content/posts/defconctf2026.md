---
title: DEFCON CTF 2026
published: 2026-05-24
description: Reverse方向个人题解
tags: [CTF, Writeup, Reverse]
category: CTF
series: CTF Writeup
seriesOrder: 4
draft: false
---
顶级国际大比赛，难度很高，尽力了，别的方向题没做

谁懂BBbird

# Reverse

## Birdhouse

根据题目提示，需要用到开源项目https://github\.com/ares\-emulator/ares

下载之后需要在areas里加载game\.z64

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MDYwM2JhMDIzN2VkMmQ2NWU5MTE1MTJjN2FhNzM2Y2RfYTg5ZjI5OTc1NjdlNzA4NzFmNzFjNmZkMGM4MDNjZTdfSUQ6NzY0Mjg1NDg1OTYzMjM2NDczMl8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

神秘小游戏来了

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=NTkwYjE0YjE0NDczMjBkZDU2Mjg1ODVkOTYxMjBiYjBfZjU5OTU0MDM2MjgxNTIyZjdkMGIwOWU3ODA1NTdjYjNfSUQ6NzY0Mjg0NjUzNzQwNzUzMjAwMV8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

配置下键位看看，没什么用，应该不是正常通过游玩得到flag的

事已至此，那就把game\.z64丢进IDA看

关键逻辑就在CODE段中，用AI辅助阅读ELF LOAD 数据即可



程序映射到RDRAM

```text
RDRAM_BASE = 0x80000400
```

虚拟地址和 buffer 偏移的对应关系

```text
offset = vaddr - 0x80000400
```

真正关键部分数据

```text
VALIDATOR_DATA = 0x80057ca0
```

换算偏移

```text
0x80057ca0 - 0x80000400 = 0x578a0
```

区域数据格式直接搓C还原就行

```c
struct validator_data {
    uint16_t constraint_count_be;
    uint8_t  reserved[6];
    struct {
        uint16_t a_be;
        uint16_t b_be;
    } pairs[constraint_count];
    uint8_t encrypted_flag[32];
};
```

得到

```text
constraint_count = 7464
encrypted_flag = fd364d4a685433acb6b55184392740db84c9c544d43f7e56ba58357d4fa4c11f
```

我们的密文就出现了，后续会用到

游戏方块属于三维grid 32\*16\*32

坐标关系等价C为

```c
index = ((x * 16 + y) * 32 + z)
```

方块id有效范围为1\-7



隐藏数据的约束含义为

```python
value = grid[a]
if value == 0:
    fail()

if value != seq:
    other = grid[b]
    if other == 0 or other == value:
        fail()
```

grid\[a\]必须放方块，当前seq不等于grid\[a\]则对应的grid\[b\]也必须放方块，并且grid\[b\]的方块类型不能等于grid\[a\]，变成7色图着色求解

整体分布为 10 \+ 10 \+ 412 \+ 204 \+108 \+10 \+179 = 933 所以要搭建933方块，在游戏里肯定搓不到



求出来grid后按约束复算一下hash seed

初始seed

```text
0x6d2b79f5
```

使用的 `xorshift32`

```python
def xorshift32(x):
    x &= 0xffffffff
    x ^= (x << 13) & 0xffffffff
    x ^= (x >> 17) & 0xffffffff
    x ^= (x << 5) & 0xffffffff
    return x & 0xffffffff
```

每遇到一个新的a时更新 seed

```python
seed ^= (unique_i * 158 + grid[a]) & 0xffffffff
seed = xorshift32(seed)
```

得到seed

```text
0xfe13cbb9
```

然后用该 seed 生成 32 字节 keystream

```python
x = seed
stream = bytearray()
for _ in range(32):
    x = (x + 0x9e3779b9) & 0xffffffff
    x = xorshift32(x)
    stream.append((x >> 8) & 0xff)
```

和密文异或

```text
fd364d4a685433acb6b55184392740db84c9c544d43f7e56ba58357d4fa4c11f
```

打穿了

**`bbb{r5p_gr4ph_c0l0r_0n_n64}`**




## My Favorite Instructions

程序不是直接比较字符串，而是先把输入转成348个三进制位数字trits

```text
flag[0:4]     -> 20 trits
flag[4:20]    -> 82 trits
flag[20:36]   -> 82 trits
flag[36:44]   -> 41 trits
flag[44:52]   -> 41 trits
flag[52:68]   -> 82 trits
```

```python
def flag_to_trits(flag: bytes):
    tr = []

    for c in flag[:4]:
        for _ in range(5):
            tr.append(c % 3)
            c //= 3

    for off, bits, digs in [
        (4, 128, 82),
        (20, 128, 82),
        (36, 64, 41),
        (44, 64, 41),
        (52, 128, 82),
    ]:
        n = int.from_bytes(flag[off:off + bits // 8], "little")
        for _ in range(digs):
            tr.append(n % 3)
            n //= 3

    assert len(tr) == 348
    return tr
```

然后就是我提到的 两个最喜欢的指令指的就是x86汇编中的bsr  bzhi

bsr的话

```text
src = 0 -> 保留 old
src = 1 -> 0
src = 2 -> 1
```

等价

```python
def bsr_tri(old, src):
    if src == 0:
        return old
    if src == 1:
        return 0
    if src == 2:
        return 1
```

如果src是普通整数就不能套用三值了，必须用bsr真实语义

```python
src.bit_length() - 1
```

后面这个非常重要

然后再来说说bzhi

```text
bzhi(a, b) = a & ((1 << b) - 1)
```

当然这个题大部分参与值都在0 1 2上，看为三值逻辑门 正好对应bsr输入值三值

### part1

第一阶段依赖前20个trits

```text
flag[0:4]
```

所以直接约束求解后就是bbb\{

```text
flag[0:4] = bbb{
```

### part2

```text
flag[4:20]
flag[20:36]
```

程序把16字节快转为82\-trit三进制整数做mask变换，密码也来支持了

```text
N = 69315507563335000426881137137421870202776768428849895573283403915458679359157
```

丢给factordb

http://www\.factordb\.com/index\.php?query=69315507563335000426881137137421870202776768428849895573283403915458679359157

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MDJlODAyNGJkZTliOGFiYzY1NTg0NTgyY2M5YzRjZjdfZTVlOTQ2ODBkODQwMGEyYmUwOTQ4OTY3MTA3MGRkMTdfSUQ6NzY0MzQ4MTYzNzc1NzQyMjc4OF8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

```text
p = 312491767943139940981443826148003062019
q = 221815467394800111963839297593696124903
```

A = q, B = p

```text
flag[4:36] = kQMM2FhlSBO4fEYFho5azaRrlTdxPsRx
```

### part3

对应了41个trits，8个字节

逆向得表

```text
table  : 0x4e590
target : 0x67930
```

15\*41\*21个三值系数 15\*21个目标trits 21个trits组成一个base\-3整数做普通整数乘加

打格LLL还原41个trits

```text
flag[36:44] = 6ue7npnj
```

### part4

也是41个trits，提取对应net后SAT求解

```text
0x26400 -> 0x325bc
```

约束输出为2

```text
flag[44:52] = ATDcm6d4
```

### part5

最后一段是16字节，也就是82个trits

```text
0x325bc -> 0x3cd00    preloop
0x3cd00 -> 0x48c82    243-round loop
0x48c91 -> 0x4d881    final checker
```

跑angr符号执行就可以

计数器从0跑到 0xf3 = 243，最后一个阶段就是dump325bc angr符号执行 合成242轮\+final checker 检查 也就拿到我们的最后一轮入口点的约束，从241轮一路像part4那样SAT反推到0轮

用初始化的preloop net求解原始的82个trits，转成16字节，收个尾，加上\}的最终约束

```text
flag[52:68] = hPe25PNGBdT9MK0}
```

这下从头开始拼接

### 最终合并flag

```text
bbb{
kQMM2FhlSBO4fEYFho5azaRrlTdxPsRx
6ue7npnj
ATDcm6d4
hPe25PNGBdT9MK0}
```


```text
bbb{kQMM2FhlSBO4fEYFho5azaRrlTdxPsRx6ue7npnjATDcm6d4hPe25PNGBdT9MK0}
```

成功还原收工

**bbb\{kQMM2FhlSBO4fEYFho5azaRrlTdxPsRx6ue7npnjATDcm6d4hPe25PNGBdT9MK0\}**



## Pixels and Nicotine

> Vapes are cheap\. Easy to buy, easy to mod, easy 
> 
> to leave somewhere\. Nicotine optional\. Reverse 
> 
> engineering required :\)
> 
> 
> 
> Note: You will need to wrap the flag with bbb\{\.\.\.\} before submitting it\.
> 
> 

\[pixels\-n\-nicotine\-8fe8fd754ee1fbc3577adeab4d95a844\.tar\.gz\]



附件给了个bin文件，Pixels，题目与像素有关系

Vapes，电子烟固件逆向？  ~~🔇I Got Smoke🚭~~

需要个看二进制的工具来拼接，Mesen，以及YY\-CHR，还有打表

实际上硬件dump取证\+固件逆向\+ROM逆向打满。。。

拿题目第一反应是我之前打过的阿里CTF，题目是pixelflow，考的il2cpp，unity逆向，不过和这道题不太一样，但是最后结果额都是像素分析，解xor和tile映射最后套flag

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MWI4NDMwNjU1YjUzODZhNzU2NDhkYzZhODE1ZjA4ODNfNWY3ODdkMjk5OWM5YWZlOTZiYzU0YTJmYThkMDZlYWZfSUQ6NzY0MzM3MTQ4NTAwNzk3MzM0M18xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

0x234000开始选中0x6000字节直到0x239FFF

提取，构建新文件 新文件头4E 45 53 1A 01 01 00 00 00 00 00 00 00 00 00 00\+复制过来的0x6000字节

模拟\.nes，用Mesen打开恢复即可成功，我们得到了一份nes游戏的ROM（被修改过的）记一下，作为hidden\.nes



同样的，base = 0x60000 length = 0x6000再扣一个\.nes（未修改过的）未改变的，记一下original\.nes

分析INES文件的PRG部分，这地方是重点，找0x0010 \~ 0x400F就行

```text
CPU address = 0xC000 + (file_offset - 0x10)
反转
**file_offset = 0x10 + (CPU address - 0xC000)**
记一下这个换算
```

改版的ROM在PRG中增加了新的跳转和routine

```text
; CPU $CA36
CA36: 4C CA E8     JMP $E8CA

; CPU $D090
D090: 4C C2 E7     JMP $E7C2
```

用Mesen看hidden\.nes 

跳E8CA看

```yaml
E8CA: B1 CE        LDA ($CE),Y
E8CC: 45 CD        EOR $CD
E8CE: 5D 88 E7     EOR $E788,X
E8D1: BC 91 E7     LDY $E791,X
E8D4: 99 00 01     STA $0100,Y
E8D7: A0 00        LDY #$00
E8D9: 60           RTS
```

跳E7C2看

```yaml
E7C2: B1 CE        LDA ($CE),Y
E7C4: 45 CD        EOR $CD
E7C6: 5D 88 E7     EOR $E788,X
E7C9: BC 91 E7     LDY $E791,X
E7CC: 99 10 01     STA $0110,Y
E7CF: A0 00        LDY #$00
E7D1: 60           RTS
```

汇编建议AI辅助观看，一坨

模拟出的逻辑炼出来是

```text
decoded = encrypted_byte XOR RAM[$00CD] XOR key[x]
screen_position = perm[x]
```

其中

```text
key  = bytes at CPU $E788 ~ $E790
perm = bytes at CPU $E791 ~ $E799
```

然后我们上面用到的CPU计算就用上了，换算iNES文件偏移

```text
$E788 -> 0x2798
$E791 -> 0x27A1
```

可读

```text
key  = 31 A4 5C 07 C9 22 E1 4B 98
perm = 04 09 01 07 03 08 05 02 06
```

断E8CA E7C2调试看RAM $00CD值为AA



```text
DA3B: A5 17        LDA $17
DA3D: 45 09        EOR $09
DA3F: 85 CC        STA $CC
DA41: 49 3E        EOR #$3E
DA43: 85 CD        STA $CD
```

人工解码用到CD = AA

再找两组指针表

还是E8C4和E7C2

借助工具翻译一下知道是 $CE/$CF指向的位置读字节

第一行

```text
low table  = CPU $D22F ~ $D237
high table = CPU $D238 ~ $D240
```

字节

```text
low  = A7 F0 D4 68 17 16 00 21 04
high = C4 E2 F7 C3 C4 E9 C0 EA C0
```

CPU指针

```text
C4A7 E2F0 F7D4 C368 C417 E916 C000 EA21 C004
```

第二行

```text
low table  = CPU $DBA0 ~ $DBA8
high table = CPU $DBA9 ~ $DBB1
```

字节

```text
low  = 84 32 D1 2C 67 30 FD 97 FC
high = E3 F9 EB FB E1 E9 FE D5 E2
```

CPU指针

```text
E384 F932 EBD1 FB2C E167 E930 FEFD D597 E2FC
```

最后表格解码

用前面得公式

```text
tile = raw_byte_at_pointer XOR AA XOR key[x]
```

第一行：RAM\[$0100 \+ perm\[x\]\]

第二行：RAM\[$0110 \+ perm\[x\]\]

打表

第一行

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ODE4MzRhMDg5NzU2MjJhNzA4NjBjYWJkNjZhZTA3ZDVfY2RlMDFlMjhiNGYxNWYwMWUxNGYxZmExNjc4MzhmMGZfSUQ6NzY0MzM3OTIyNDQ4NDk0MTAxNl8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

第二行

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MzdlYWFlMzlkNWViMmIxMTM4NmE1YzA1YmRkNTE3MmNfODU1YTc3NjAzMzYxOTU1OGZmZmM0YzI4OWE1NTA1ODhfSUQ6NzY0MzM3OTM5NzEwNTgxNDUwMF8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

CD = AA

打开hidden\.nes看CHR，看tile图案

交给YY\-CHR查tile对应字符

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=YjE5ZGY5M2NjMDhmNmVkMWE2ZjI0MzUyMWNiNGE3MjZfOTUxNjU3NGIxMTJmMGNkNGMzYWQwNDgyZTcyZmU4MWVfSUQ6NzY0MzM4MTkxODY2NjQ5MzExNl8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ZGIwOWExZDAyNWRlYzAwNzllZWMyYzg3NzRlNjk5MGRfNmJiODIyOGZiZDMyNWEzNzlmYWVjYTVlMjNiNjg4MWVfSUQ6NzY0MzM2NDEzNzQ4NTAyODUzM18xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)



tile映射打表

第一行

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=YjdjZDAxOTg5NjhkZjY2NTNiZWM5NTFmMDZjZDZmMjBfYTQ5ZGJlMDJkNzM3OWIxMmM5NWU3Mzg5MDg5OTlkMmFfSUQ6NzY0MzM3OTYzMzg1NzE1NDAwNl8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

内存顺序KX9H\_A9CA

反向读**AC9A\_H9XK**

第二行

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=NGMyMzVlY2Y4ZWIxYWUzY2JhYzhiMDExMWFiMmRlMTdfZDBmZWM2Y2RiODJlN2M3YjBmNWYxZDU3NDg4NzZiOWZfSUQ6NzY0MzM3OTg3MDA2MzcwOTM4NF8xNzgwMzg3MTEyOjE3ODA0NzM1MTJfVjM)

内存顺序\_\_\_\_\_3YP\_

反向读\_PY3\_\_\_\_

拼接AC9A\_H9XK\_PY3\_\_\_\_

然后不行，要去一下padding，最后能得到AC9A\_H9XK\_PY3

套flag格式交了

打穿

**bbb\{AC9A\_H9XK\_PY3\}**
