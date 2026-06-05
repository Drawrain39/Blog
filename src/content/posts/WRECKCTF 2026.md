---
title: WRECKCTF 2026
published: 2026-04-19
description: Reverse方向个人题解
tags: [CTF, Writeup, Reverse]
category: CTF
series: CTF Writeup
seriesOrder: 3
draft: false
---
> 国外小众简单赛事罢了，最后ban完后结榜个人打了第二，还不错，AK except 3\(包括一个过本地但是远程靶机坏了的pwn\.\.\.）

全方向但仅放Re，美国比赛so write up in English.

# Reverse

## **baby\-rev**

Question Source Code

```python
#!/usr/bin/env python3
T = bytes.fromhex("7066444d5033220a5b08d6a2fcc38ca7a788c2a17b6a15554d78341b")

flag = input("flag: ")
if len(flag) == len(T) and all(
    ord(flag[i]) ^ ((i * 13 + 7) & 0xFF) == T[i] for i in range(len(T))
):
    print("correct!")
else:
    print("nope")

```

There's nothing much to say, just directly reverse one step back, so easy 

```python
#!/usr/bin/env python3
T = bytes.fromhex("7066444d5033220a5b08d6a2fcc38ca7a788c2a17b6a15554d78341b")

def main():
    flag = "".join(chr(b ^ ((i * 13 + 7) & 0xFF)) for i, b in enumerate(T))
    print(flag)

if __name__ == "__main__":
    main()
```

wreck\{wh4t\_4\_s1mpl3\_pr0gr4m\}

## **pipeline**

The problem essentially involves feeding the input 32 ByteDance flag into `_Q`'s 32 transformations, and finally requiring the result to equal `_T`

Most operations are clearly reversible

- `_0`: XOR by key, and the inverse operation is still itself

- `_1`: Add by key, and the inverse operation is subtract

- `_2`: Subtract by key, and the inverse operation is addition

- `_3`: Circular left shift, and its inverse operation is circular right shift

- `_4`: Permutation, and its inverse operation is inverse permutation

- `_5`: S\-box substitution, and the inverse operation is reverse lookup table

- `_6`: reverse, the inverse operation is still itself

- `_7`: Swap the front and back halves, and the inverse operation is still itself

- `_8`: Prefix XOR, the inverse operation satisfies `orig[i] = out[i] ^ out[i - 1]`

- `_9`: Just find the multiplicative inverse modulo `256` by multiplying with an odd constant 

What is truly less straightforward is `_A` and `_B`

```python
c = bytes(x[i:i + 3])
d = hash(c).digest()[:3]
x[i:i + 3] = bytes(p ^ q for p, q in zip(c, d))
```

They only affect 3 consecutive ByteDance, so when reaching the corresponding position during the reverse process, all `2^24` possible inputs can be enumerated for the current target 3 ByteDance to find the ones that satisfy 

```python
chunk ^ hash(chunk)[:3] == target
```

preimage 

There are two key pieces of information here

- `_B` has only one preimage for the target `f51d49`: `4c94db`

- `_A`'s target `cfafe4` has three preimages: 

 - `79335e`

- `a44c66`

- `e28388`

Bringing these three candidates back to the entire inverse chain respectively, only `e28388` can ultimately restore a valid flag that satisfies `_c()`\.

```python
#!/usr/bin/env python3
import hashlib
import random

def g(seed, n):
    r = random.Random(seed)
    arr = list(range(n))
    r.shuffle(arr)
    return arr

S = g(0xBEEF1234, 256)
P = g(0xCAFEBABE, 32)
T = bytes.fromhex("34ad7a3e4331511d979f075ee8b4619a1aaee35184cb1f1d933e948631ec9f8e")

def xor_bytes(x, k):
    for i in range(len(x)):
        x[i] ^= k[i % len(k)]

def add_bytes(x, k):
    for i in range(len(x)):
        x[i] = (x[i] + k[i % len(k)]) & 0xFF

def sub_bytes(x, k):
    for i in range(len(x)):
        x[i] = (x[i] - k[i % len(k)]) & 0xFF

def rol_bytes(x, a):
    a &= 7
    if not a:
        return
    for i, b in enumerate(x):
        x[i] = ((b << a) | (b >> (8 - a))) & 0xFF

def ror_bytes(x, a):
    a &= 7
    if not a:
        return
    for i, b in enumerate(x):
        x[i] = ((b >> a) | ((b << (8 - a)) & 0xFF)) & 0xFF

def permute(x, p):
    out = bytearray(len(x))
    for i, j in enumerate(p):
        out[i] = x[j]
    x[:] = out

def inv_permute(x, p):
    out = bytearray(len(x))
    for i, j in enumerate(p):
        out[j] = x[i]
    x[:] = out

def sbox(x, table):
    for i in range(len(x)):
        x[i] = table[x[i]]

def inv_sbox(x, table):
    inv = [0] * 256
    for i, v in enumerate(table):
        inv[v] = i
    for i in range(len(x)):
        x[i] = inv[x[i]]

def rev(x):
    x.reverse()

def half_swap(x):
    n = len(x) // 2
    left = bytes(x[:n])
    x[:n] = x[n:]
    x[n:] = left

def prefix_xor(x):
    for i in range(1, len(x)):
        x[i] ^= x[i - 1]

def inv_prefix_xor(x):
    out = bytearray(len(x))
    out[0] = x[0]
    for i in range(1, len(x)):
        out[i] = x[i] ^ x[i - 1]
    x[:] = out

def mul_bytes(x, k):
    for i in range(len(x)):
        x[i] = (x[i] * k[i % len(k)]) & 0xFF

def inv_mul_bytes(x, k):
    invk = [pow(v, -1, 256) for v in k]
    for i in range(len(x)):
        x[i] = (x[i] * invk[i % len(invk)]) & 0xFF

def hash_mix(x, idx, algo):
    chunk = bytes(x[idx : idx + 3])
    d = getattr(hashlib, algo)(chunk).digest()[:3]
    x[idx : idx + 3] = bytes(a ^ b for a, b in zip(chunk, d))

def brute_hash_preimages(algo, target3):
    res = []
    h = getattr(hashlib, algo)
    for v in range(1 << 24):
        chunk = v.to_bytes(3, "big")
        d = h(chunk).digest()[:3]
        if bytes(a ^ b for a, b in zip(chunk, d)) == target3:
            res.append(chunk)
    return res

OPS = [
    ("xor", b"BUZZBUZZ"),
    ("add", b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"),
    ("rol", 3),
    ("sbox", S),
    ("perm", P),
    ("pxor", None),
    ("sub", b"\x42\x13\x37\x99"),
    ("swap", None),
    ("xor", b"\xab\xcd\xef\x12"),
    ("mul", [3, 5, 7, 11]),
    ("rol", 2),
    ("sbox", S),
    ("rev", None),
    ("add", b"\x01\x02\x03\x04"),
    ("md5", 4),
    ("perm", P),
    ("xor", b"\x55\xaa\x55\xaa"),
    ("rol", 1),
    ("sbox", S),
    ("sub", b"\x11\x22\x33\x44"),
    ("pxor", None),
    ("swap", None),
    ("mul", [3, 11, 13, 17]),
    ("sha256", 12),
    ("perm", P),
    ("rev", None),
    ("xor", b"\xf0\x0d\xca\xfe"),
    ("add", b"\x77\x88\x99\xaa"),
    ("mul", [5, 9, 11, 13]),
    ("rol", 4),
    ("sbox", S),
    ("sub", b"\x99\x55\x33\x11"),
]

def apply_op(x, op):
    typ, arg = op
    if typ == "xor":
        xor_bytes(x, arg)
    elif typ == "add":
        add_bytes(x, arg)
    elif typ == "sub":
        sub_bytes(x, arg)
    elif typ == "rol":
        rol_bytes(x, arg)
    elif typ == "perm":
        permute(x, arg)
    elif typ == "sbox":
        sbox(x, arg)
    elif typ == "rev":
        rev(x)
    elif typ == "swap":
        half_swap(x)
    elif typ == "pxor":
        prefix_xor(x)
    elif typ == "mul":
        mul_bytes(x, arg)
    elif typ in ("md5", "sha256"):
        hash_mix(x, arg, typ)
    else:
        raise ValueError(typ)

def check(flag):
    if not (flag.startswith(b"wreck{") and flag.endswith(b"}")):
        return False
    if not all(0x20 <= c <= 0x7E for c in flag):
        return False
    x = bytearray(flag)
    for op in OPS:
        apply_op(x, op)
    return bytes(x) == T

def apply_inv_block(x, block):
    for typ, arg in block:
        if typ == "xor":
            xor_bytes(x, arg)
        elif typ == "add":
            sub_bytes(x, arg)
        elif typ == "sub":
            add_bytes(x, arg)
        elif typ == "rol":
            ror_bytes(x, arg)
        elif typ == "perm":
            inv_permute(x, arg)
        elif typ == "sbox":
            inv_sbox(x, arg)
        elif typ == "rev":
            rev(x)
        elif typ == "swap":
            half_swap(x)
        elif typ == "pxor":
            inv_prefix_xor(x)
        elif typ == "mul":
            inv_mul_bytes(x, arg)
        else:
            raise ValueError(typ)

def solve():
    x = bytearray(T)

    tail = [
        ("sub", b"\x99\x55\x33\x11"),
        ("sbox", S),
        ("rol", 4),
        ("mul", [5, 9, 11, 13]),
        ("add", b"\x77\x88\x99\xaa"),
        ("xor", b"\xf0\x0d\xca\xfe"),
        ("rev", None),
        ("perm", P),
    ]
    apply_inv_block(x, tail)

    b_candidates = brute_hash_preimages("sha256", bytes(x[12:15]))
    assert len(b_candidates) == 1
    x[12:15] = b_candidates[0]

    mid = [
        ("mul", [3, 11, 13, 17]),
        ("swap", None),
        ("pxor", None),
        ("sub", b"\x11\x22\x33\x44"),
        ("sbox", S),
        ("rol", 1),
        ("xor", b"\x55\xaa\x55\xaa"),
        ("perm", P),
    ]
    apply_inv_block(x, mid)

    a_candidates = brute_hash_preimages("md5", bytes(x[4:7]))

    head = [
        ("add", b"\x01\x02\x03\x04"),
        ("rev", None),
        ("sbox", S),
        ("rol", 2),
        ("mul", [3, 5, 7, 11]),
        ("xor", b"\xab\xcd\xef\x12"),
        ("swap", None),
        ("sub", b"\x42\x13\x37\x99"),
        ("pxor", None),
        ("perm", P),
        ("sbox", S),
        ("rol", 3),
        ("add", b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"),
        ("xor", b"BUZZBUZZ"),
    ]

    for a in a_candidates:
        y = bytearray(x)
        y[4:7] = a
        apply_inv_block(y, head)
        if check(bytes(y)):
            return bytes(y)

    raise RuntimeError("flag not found")

if __name__ == "__main__":
    print(solve().decode())

```

wreck\{h4shing\_1n\_my\_p1p3l1n3???\}

## **gotohell\-1**

First look at `main`

The input length must be ` 39 `\. 

The end does not involve byte\-by\-byte comparison; instead, it first runs a large segment of arithmetic/XOR obfuscation, and finally checks several sets of 32\-bit states: 

```c
if ( v16 != -2103969039 )
  goto LABEL_55;

if ( v15 == -1082669001
  && n722405961 == 722405961
  && v13 == -2111249330
  && n1525289352 == 1525289352
  && v10 == -309151393
  && n1504177626 == 1504177626 )
```

Although there are many branches in the middle, most of them only depend on a few blocks after the input is treated as a 32\-bit little\-endian integer:

`s` corresponds to the first 4 ByteDance

`v19` corresponds to Bytes 5 to 8 

`v27` corresponds to the last 3 ByteDance

The flag format is ` wreck{...} ` Subsequent consideration of constrained blasting 

After ` wreck{ ` is stuffed into the first few 32\-bit blocks in little\-endian, many bit judgments will be directly fixed: 

`(s & 0x04000000)!= 0` is false

`(s & 0x00000100)!= 0` is false

`(s & 0x00000020)!= 0` is true

`(s & 0x00000400)!= 0` is false

`(v19 & 0x200)!= 0` is true

`(v19 & 0x20)!= 0` is true

`(v19 & 8)!= 0` is true

`(v19 & 0x80) == 0` is true

Additionally, since the end must be `}`, ` the corresponding position of v27 ` will also be fixed, so the main chain only has one feasible and successful path left\. 

It has changed from a messy goto obfuscation to a fixed single path, and then collected the bit vector expressions on the path 

Request the remaining 33 characters 

```python
from __future__ import annotations

import json
import re
import time

import z3
from pysat.solvers import Cadical153

# These 12 branch decisions are fixed once you know the format is `wreck{...}`.
FIXED_PATH = [
    False,  # (s & 0x04000000) != 0
    True,   # (v19 & 0x200) != 0
    False,  # (s & 0x100) != 0
    True,   # (v19 & 0x20) != 0
    True,   # (v19 & 8) != 0
    True,   # (s & 0x20) != 0
    True,   # (v27 & 0x400000) != 0
    True,   # (v19 & 0x80) == 0
    False,  # (s & 0x400) != 0
    True,   # (s & 0x20000000) != 0
    False,  # (s & 0x10000000) != 0
    False,  # (s & 0x08000000) != 0
]

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_{}"

def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\n", " ")).strip()

def split_and(expr: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0 and expr.startswith("&&", i):
            parts.append("".join(cur).strip())
            cur = []
            i += 2
            continue
        cur.append(ch)
        i += 1
    if cur:
        parts.append("".join(cur).strip())
    return parts

class MiniCParser:
    def __init__(self, text: str):
        self.text = text
        self.i = 0

    def skip_ws(self) -> None:
        while self.i < len(self.text) and self.text[self.i].isspace():
            self.i += 1

    def starts(self, token: str) -> bool:
        return self.text.startswith(token, self.i)

    def read_paren(self) -> str:
        assert self.text[self.i] == "("
        depth = 0
        start = self.i + 1
        while self.i < len(self.text):
            ch = self.text[self.i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    out = self.text[start:self.i]
                    self.i += 1
                    return out
            self.i += 1
        raise ValueError("unclosed parenthesis")

    def read_stmt(self):
        self.skip_ws()
        if self.i >= len(self.text):
            return None

        if self.starts("if"):
            self.i += 2
            self.skip_ws()
            cond = self.read_paren().strip()
            then_node = self.read_stmt()
            self.skip_ws()
            else_node = None
            if self.starts("else"):
                self.i += 4
                else_node = self.read_stmt()
            return ("if", cond, then_node, else_node)

        if self.text[self.i] == "{":
            self.i += 1
            body = []
            while True:
                self.skip_ws()
                if self.text[self.i] == "}":
                    self.i += 1
                    return ("block", body)
                body.append(self.read_stmt())

        if self.starts("goto LABEL_55"):
            j = self.text.index(";", self.i)
            self.i = j + 1
            return ("goto_fail",)

        if self.starts("LABEL_55:"):
            self.i += len("LABEL_55:")
            return ("label", "LABEL_55")

        j = self.text.index(";", self.i)
        stmt = self.text[self.i:j].strip()
        self.i = j + 1
        return ("stmt", stmt)

def load_main_tail():
    data = json.load(open(".ida_main_full.json", "r", encoding="utf-8"))["code"]
    data = re.sub(r"/**\***.*?**\***/", "", data, flags=re.S)
    data = re.sub(r"(0x[0-9A-Fa-f]+|\d+)([uUlL]+)\b", r"\1", data)

    start = data.index("v12 = ((v23")
    final_if = data.index("if ( v15 == -1082669001")
    end = data.index("{", final_if)
    text = data[start:end]

    parser = MiniCParser(text)
    ast = []
    while True:
        node = parser.read_stmt()
        if node is None:
            return ast
        ast.append(node)

def build_constraints(ast):
    words = [z3.BitVec(f"x{i}", 32) for i in range(10)]
    values = {
        "s": words[0],
        "v19": words[1],
        "v20": words[2],
        "n1504177626_1": words[3],
        "v22": words[4],
        "v23": words[5],
        "v24": words[6],
        "v25": words[7],
        "n1525289352_1": words[8],
        "v27": words[9],
        "stdout": z3.BitVecVal(0, 64),
        "stdin": z3.BitVecVal(0, 64),
    }
    for name in [
        "v8",
        "n1504177626",
        "v10",
        "n1525289352",
        "v12",
        "v13",
        "n722405961",
        "v15",
        "v16",
        "v17",
    ]:
        values[name] = None

    def eval_expr(expr: str, env: dict):
        return eval(normalize(expr), {"__builtins__": None}, {k: v for k, v in env.items() if v is not None})

    def eval_cond(cond: str, env: dict):
        cond = normalize(cond)
        pieces = split_and(cond)
        if len(pieces) > 1:
            return z3.And(*[eval_cond(piece, env) for piece in pieces])
        return eval_expr(cond, env)

    class State:
        def __init__(self):
            self.env = dict(values)
            self.constraints = []
            self.done = False

    def walk(node, state: State, branch_idx: int):
        kind = node[0]

        if kind == "block":
            for sub in node[1]:
                state, branch_idx = walk(sub, state, branch_idx)
            return state, branch_idx

        if kind == "stmt":
            text = normalize(node[1])

            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s***\(**.***\)**$", text):
                return state, branch_idx

            if text.startswith("return "):
                state.done = True
                return state, branch_idx

            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*([**\^\+\-**]?=)\s*(.*)$", text)
            if m:
                name, op, expr = m.groups()
                rhs = eval_expr(expr, state.env)
                cur = state.env.get(name)
                if op == "=":
                    state.env[name] = rhs
                elif op == "+=":
                    state.env[name] = cur + rhs
                elif op == "-=":
                    state.env[name] = cur - rhs
                elif op == "^=":
                    state.env[name] = cur ^ rhs
            return state, branch_idx

        if kind == "if":
            cond, then_node, else_node = node[1], node[2], node[3]

            if "v15 == -1082669001" in cond and "n722405961 == 722405961" in cond:
                state.constraints.append(eval_cond(cond, state.env))
                state.done = True
                return state, branch_idx

            if then_node[0] == "goto_fail" and else_node is None:
                state.constraints.append(z3.Not(eval_cond(cond, state.env)))
                return state, branch_idx

            take_then = FIXED_PATH[branch_idx]
            branch_idx += 1
            test = eval_cond(cond, state.env)
            state.constraints.append(test if take_then else z3.Not(test))
            return walk(then_node if take_then else else_node, state, branch_idx)

        return state, branch_idx

    state = State()
    branch_idx = 0
    for node in ast:
        state, branch_idx = walk(node, state, branch_idx)
        if state.done:
            break

    return words, state.constraints

def add_flag_shape_constraints(goal: z3.Goal, words) -> None:
    for i in range(10):
        bit_limit = 24 if i == 9 else 32
        for bit in range(bit_limit):
            alias = z3.Bool(f"x{i}_b{bit}")
            goal.add(alias == (z3.Extract(bit, bit, words[i]) == 1))

    goal.add(z3.Extract(31, 24, words[9]) == 0)

    for idx, ch in enumerate(b"wreck{"):
        word_id = idx // 4
        shift = (idx % 4) * 8
        goal.add(z3.Extract(shift + 7, shift, words[word_id]) == ch)

    goal.add(z3.Extract(23, 16, words[9]) == ord("}"))

    alphabet = [ord(c) for c in ALPHABET]
    for i in range(39):
        word_id = i // 4
        shift = (i % 4) * 8
        byte = z3.Extract(shift + 7, shift, words[word_id])
        goal.add(z3.Or(*[byte == c for c in alphabet]))

def cnf_from_goal(goal: z3.Goal):
    cnf = z3.Then("simplify", "bit-blast", "aig", "tseitin-cnf")(goal)[0]

    varmap: dict[str, int] = {}
    clauses: list[list[int]] = []

    def lit_to_int(lit) -> int:
        sign = 1
        if z3.is_not(lit):
            sign = -1
            lit = lit.arg(0)
        name = lit.decl().name()
        if name not in varmap:
            varmap[name] = len(varmap) + 1
        return sign * varmap[name]

    for formula in cnf:
        if z3.is_or(formula):
            clauses.append([lit_to_int(child) for child in formula.children()])
        else:
            clauses.append([lit_to_int(formula)])

    return varmap, clauses

def decode_model(model: set[int], varmap: dict[str, int]) -> str:
    out = []
    for i in range(39):
        word_id = i // 4
        bitoff = (i % 4) * 8
        byte = 0
        for j in range(8):
            name = f"x{word_id}_b{bitoff + j}"
            if varmap.get(name, 0) in model:
                byte |= 1 << j
        out.append(byte)
    return bytes(out).decode()

def recover_flag() -> str:
    ast = load_main_tail()
    words, path_constraints = build_constraints(ast)

    goal = z3.Goal()
    add_flag_shape_constraints(goal, words)
    goal.add(*path_constraints)

    varmap, clauses = cnf_from_goal(goal)
    with Cadical153(bootstrap_with=clauses) as solver:
        if not solver.solve():
            raise RuntimeError("solver returned UNSAT")
        model_data = solver.get_model()
        if model_data is None:
            raise RuntimeError("solver did not return a model")
        model = {v for v in model_data if v > 0}
    return decode_model(model, varmap)

if __name__ == "__main__":
    start = time.time()
    flag = recover_flag()
    print(flag)
    print(f"[+] solved in {time.time() - start:.2f}s")

```

wreck\{n0w\_h34d3d\_t0\_3xtr4\_h3ll\_8b2f4e9\}
