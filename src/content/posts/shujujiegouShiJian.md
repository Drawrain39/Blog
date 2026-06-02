---
title: 数据结构实践
published: 2026-05-29
description: 大一下数据结构实践题目收集
tags: [数据结构, notes]
category: C++
draft: false
---
---
# 实践一

## A. 新朋友人数

### 题目描述

新年快到了，天勤准备搞一个聚会。已经知道现有会员 `N` 人，把会员从 `1` 到 `N` 编号，其中会长的号码是 `N` 号。

凡是和会长是老朋友的，那么该会员的号码肯定和 `N` 有大于 `1` 的公约数，否则都是新朋友。

现在会长想知道究竟有几个新朋友，请编程计算。

本题本质是求欧拉函数 `phi(N)`，也就是小于 `N` 且与 `N` 互质的正整数个数。

### 输入

第一行是测试数据的组数 `CN`，接着有 `CN` 行正整数 `N`，表示会员人数。

### 输出

对于每一个 `N`，输出一行新朋友的人数。

### 样例输入

```text
2
25608
24027
```

### 样例输出

```text
7680
16016
```

### 解题思路

如果一个编号 `x` 和会长编号 `N` 互质，即：

```text
gcd(x, N) = 1
```

那么这个人就是新朋友

因此答案就是欧拉函数 `phi(N)`

因为题目中 `N < 32768`，可以提前预处理出所有 `phi` 值。初始化时令 `phi[i] = i`，然后用筛法枚举质因子，遇到质因子 `p` 时更新：

```text
phi[j] = phi[j] / p * (p - 1)
```

### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
int main(){
    const int max = 32768;
    vector<int> p(max +1);
    for(int i = 0; i <= max; i++){
        p[i] = i;
    }
    p[1] = 1;
    for(int i = 2; i <= max; i++){
        if(p[i] == i){
            for(int j = i; j <= max; j += i){
                p[j] = p[j] / i * (i - 1);
            }
        }
    }
    int cn;
    cin >> cn;
    while (cn--){
        int n;
        cin >> n;
        cout << p[n] << endl;
    }
    return 0;
}
```

---

## B. 互质整数个数

### 题目描述

给你一个正整数 `n`，请问有多少个比 `n` 小的且与 `n` 互质的正整数？

两个整数互质的意思是，这两个整数没有比 `1` 大的公约数。

### 输入

输入包含多组测试数据。

每组输入是一个正整数 `n`，`n <= 1000000000`。

当 `n = 0` 时，输入结束。

### 输出

对于每组输入，输出比 `n` 小的且与 `n` 互质的正整数个数。

### 样例输入

```text
7
12
0
```

### 样例输出

```text
6
4
```

### 解题思路

本题仍然是求欧拉函数 `phi(n)`。

不过本题的 `n` 最大可以到 `1000000000`，不能像 A 题一样预处理到 `n`，所以需要对每个输入的 `n` 单独分解质因数。

欧拉函数公式为：

```text
phi(n) = n * (1 - 1 / p1) * (1 - 1 / p2) * ...
```

其中 `p1, p2, ...` 是 `n` 的不同质因子。

### 最终代码

```cpp
#include <iostream>
using namespace std;
#define int long long
int p(int n) {
    int ans = n;

    for (int i = 2; i * i <= n; ++i) {
        if (n % i == 0) {
            ans = ans / i * (i - 1);
            while (n % i == 0) {
                n /= i;
            }
        }
    }
    if (n > 1) {
        ans = ans / n * (n - 1);
    }
    return ans;
}
signed main() {
    int n;
    while (cin >> n && n != 0) {
        cout << p(n) << endl;
    }

    return 0;
}
```

---

## C. 约瑟夫问题

### 题目描述

`n` 个人围成一圈，按 `1` 到 `n` 的顺序编号。

从第一个人开始报数，从 `1` 到 `m` 报数，凡报到 `m` 的人退出圈子，问最后留下的是原来的第几号。

### 输入

首先输入两个正整数 `n` 和 `m`。

`n` 表示 `n` 个人围成一个圈子，`n >= 2`。

`m` 表示从 `1` 报数到 `m` 的人退出，`1 <= m`。

### 输出

输出最后剩下的人的编号。

### 样例输入

```text
2 3
```

### 样例输出

```text
2
```

### 解题思路

经典约瑟夫问题

用 `0` 开始编号时，设 `f(i)` 表示 `i` 个人时最后留下来的人的编号

递推公式为：

```text
f(1) = 0
f(i) = (f(i - 1) + m) % i
```

最后题目编号从 `1` 开始，所以输出：

```text
f(n) + 1
```

### 最终代码

```cpp
#include <iostream>
using namespace std;
#define int long long
signed main() {
    int n, m;
    cin >> n >> m;
    int ans = 0;
    for (int i = 1; i <= n; ++i) {
        ans = (ans + m) % i;
    }
    cout << ans + 1 << endl;
    return 0;
}
```

---

## D. 十进制转 R 进制

### 题目描述

编写程序演示把一个 `10` 进制整数转换为 `R` 进制的转换结果。

超过 `9` 的数字符号显示为 `A、B、C...` 等字母。

### 输入

输入正整数 `N` 和 `R`，空格分隔。

`N` 是输入的十进制数，`R` 是需要转换的进制数，`2 <= R <= 20`。

### 输出

输出将 `10` 进制整数转换为 `R` 进制后的结果。

### 样例输入

```text
10 16
```

### 样例输出

```text
A
```

### 解题思路

进制转换使用“除 `R` 取余法”：

1. 每次用 `N % R` 得到当前最低位。
2. 再令 `N = N / R`。
3. 重复直到 `N` 为 `0`。
4. 因为先得到的是低位，所以需要用栈逆序输出。

例如 `10` 转 `16` 进制：

```text
10 % 16 = 10
```

`10` 对应十六进制字符 `A`。

### 最终代码

```cpp
#include <iostream>
#include <stack>
using namespace std;
#define int long long
signed main() {
    int n, r;
    cin >> n >> r;
    char digit[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    stack<char> s;
    if (n == 0) {
        cout << 0 << endl;
        return 0;
    }
    while (n > 0) {
        s.push(digit[n % r]);
        n /= r;
    }
    while (!s.empty()) {
        cout << s.top();
        s.pop();
    }
    cout << endl;
    return 0;
}
```

---

## E. 整数求和式的计算

### 题目描述

输入两个整数的求和式，比如 `1+2=`，输出求和式和对应结果。

### 输入

一个求和式，形如：

```text
a+b=
```

### 输出

输出求和式及对应结果。

### 样例输入

```text
1+2=
```

### 样例输出

```text
1+2=3
```

### 解题思路

输入格式固定为：

```text
整数 + 整数 =
```

所以可以直接依次读入：

```text
a、+、b、=
```

然后输出原式以及 `a + b` 的结果。

### 最终代码

```cpp
#include <iostream>
using namespace std;
#define int long long
signed main() {
    int a, b;
    char plus, equal;
    cin >> a >> plus >> b >> equal;
    cout << a << plus << b << equal << a + b << endl;
    return 0;
}
```

---

## F. 波兰表达式

### 题目描述

波兰表达式是一种把运算符前置的算术表达式。

例如普通表达式：

```text
2 + 3
```

它的波兰表示法为：

```text
+ 2 3
```

波兰表达式的优点是运算符之间不必有优先级关系，也不必用括号改变运算次序。

例如：

```text
(2 + 3) * 4
```

它的波兰表示法为：

```text
* + 2 3 4
```

本题求解波兰表达式的值，其中运算符包括 `+ - * /` 四个。

### 输入

输入为一行，其中运算符和运算数之间都用空格分隔，运算数是浮点数。

### 输出

输出为一行，表达式的值，保留 `6` 位小数。

### 样例输入

```text
* + 11.0 12.0 + 24.0 35.0
```

### 样例输出

```text
1357.000000
```

### 解题思路

波兰表达式具有天然递归结构：

```text
运算符 左表达式 右表达式
```

所以可以从左往右读入。

如果读到的是数字，直接返回它的值。

如果读到的是运算符，就递归计算它后面的两个表达式，然后根据运算符进行计算。

例如：

```text
* + 11.0 12.0 + 24.0 35.0
```

可以理解为：

```text
(11.0 + 12.0) * (24.0 + 35.0)
```

结果为：

```text
23.0 * 59.0 = 1357.0
```

### 最终代码

```cpp
#include <iostream>
#include <iomanip>
#include <string>
using namespace std;
double solve() {
    string s;
    cin >> s;
    if (s == "+" || s == "-" || s == "*" || s == "/") {
        double a = solve();
        double b = solve();
        if (s == "+") {
            return a + b;
        }
        if (s == "-") {
            return a - b;
        }
        if (s == "*") {
            return a * b;
        }
        return a / b;
    }
    return stod(s);
}
signed main() {
    cout << fixed << setprecision(6) << solve() << endl;
    return 0;
}
```

---

## G. 合并队列

### 题目描述

上体育课的时候，老师已经把班级同学排成了两个队列，而且每个队列都是按照从低到高排好队。

现在需要把两个队列合并，合并后需要保证还是从低到高排列。

请编程实现合并队列。

### 输入

第 `1` 行为 `n`，表示开始排成的每个队列的长度。

第 `2、3` 行分别是代表从小到大的 `n` 个整数，每行的整数之间用一个空格间隔。

### 输出

输出占一行，为从小到大的整数，每个整数之间间隔一个空格。

### 样例输入

```text
5
1 3 5 8 15
2 3 4 6 9
```

### 样例输出

```text
1 2 3 3 4 5 6 8 9 15
```

### 解题思路

因为两个队列本来就是从小到大排列的，所以不需要重新排序。

每次只需要比较两个队首元素：

```text
a.front()
b.front()
```

哪个小，就先输出哪个，并让它出队。

如果一个队列已经为空，就直接输出另一个队列剩下的所有元素。

### 最终代码

```cpp
#include <iostream>
#include <queue>
using namespace std;
#define int long long
signed main() {
    int n;
    cin >> n;
    queue<int> a, b;
    for (int i = 0; i < n; ++i) {
        int x;
        cin >> x;
        a.push(x);
    }
    for (int i = 0; i < n; ++i) {
        int x;
        cin >> x;
        b.push(x);
    }
    while (!a.empty() || !b.empty()) {
        int x;
        if (b.empty() || (!a.empty() && a.front() <= b.front())) {
            x = a.front();
            a.pop();
        } else {
            x = b.front();
            b.pop();
        }
        cout << x;
        if (!a.empty() || !b.empty()) {
            cout << ' ';
        }
    }
    cout << endl;
    return 0;
}
```

---
