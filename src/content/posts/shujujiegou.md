---
title: 数据结构合集
published: 2026-05-29
description: 大一下数据结构作业+实践+笔记全收集
tags: [数据结构, notes]
category: C++
series: C++ 与数据结构
seriesOrder: 2
draft: false
---

## 数据结构实践

### 实践一

#### A. 新朋友人数

##### 题目描述

新年快到了，天勤准备搞一个聚会。已经知道现有会员 `N` 人，把会员从 `1` 到 `N` 编号，其中会长的号码是 `N` 号。

凡是和会长是老朋友的，那么该会员的号码肯定和 `N` 有大于 `1` 的公约数，否则都是新朋友。

现在会长想知道究竟有几个新朋友，请编程计算。

本题本质是求欧拉函数 `phi(N)`，也就是小于 `N` 且与 `N` 互质的正整数个数。

##### 输入

第一行是测试数据的组数 `CN`，接着有 `CN` 行正整数 `N`，表示会员人数。

##### 输出

对于每一个 `N`，输出一行新朋友的人数。

##### 样例输入

```text
2
25608
24027
```

##### 样例输出

```text
7680
16016
```

##### 解题思路

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

##### 最终代码

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

#### B. 互质整数个数

##### 题目描述

给你一个正整数 `n`，请问有多少个比 `n` 小的且与 `n` 互质的正整数？

两个整数互质的意思是，这两个整数没有比 `1` 大的公约数。

##### 输入

输入包含多组测试数据。

每组输入是一个正整数 `n`，`n <= 1000000000`。

当 `n = 0` 时，输入结束。

##### 输出

对于每组输入，输出比 `n` 小的且与 `n` 互质的正整数个数。

##### 样例输入

```text
7
12
0
```

##### 样例输出

```text
6
4
```

##### 解题思路

本题仍然是求欧拉函数 `phi(n)`。

不过本题的 `n` 最大可以到 `1000000000`，不能像 A 题一样预处理到 `n`，所以需要对每个输入的 `n` 单独分解质因数。

欧拉函数公式为：

```text
phi(n) = n * (1 - 1 / p1) * (1 - 1 / p2) * ...
```

其中 `p1, p2, ...` 是 `n` 的不同质因子。

##### 最终代码

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

#### C. 约瑟夫问题

##### 题目描述

`n` 个人围成一圈，按 `1` 到 `n` 的顺序编号。

从第一个人开始报数，从 `1` 到 `m` 报数，凡报到 `m` 的人退出圈子，问最后留下的是原来的第几号。

##### 输入

首先输入两个正整数 `n` 和 `m`。

`n` 表示 `n` 个人围成一个圈子，`n >= 2`。

`m` 表示从 `1` 报数到 `m` 的人退出，`1 <= m`。

##### 输出

输出最后剩下的人的编号。

##### 样例输入

```text
2 3
```

##### 样例输出

```text
2
```

##### 解题思路

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

##### 最终代码

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

#### D. 十进制转 R 进制

##### 题目描述

编写程序演示把一个 `10` 进制整数转换为 `R` 进制的转换结果。

超过 `9` 的数字符号显示为 `A、B、C...` 等字母。

##### 输入

输入正整数 `N` 和 `R`，空格分隔。

`N` 是输入的十进制数，`R` 是需要转换的进制数，`2 <= R <= 20`。

##### 输出

输出将 `10` 进制整数转换为 `R` 进制后的结果。

##### 样例输入

```text
10 16
```

##### 样例输出

```text
A
```

##### 解题思路

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

##### 最终代码

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

#### E. 整数求和式的计算

##### 题目描述

输入两个整数的求和式，比如 `1+2=`，输出求和式和对应结果。

##### 输入

一个求和式，形如：

```text
a+b=
```

##### 输出

输出求和式及对应结果。

##### 样例输入

```text
1+2=
```

##### 样例输出

```text
1+2=3
```

##### 解题思路

输入格式固定为：

```text
整数 + 整数 =
```

所以可以直接依次读入：

```text
a、+、b、=
```

然后输出原式以及 `a + b` 的结果。

##### 最终代码

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

#### F. 波兰表达式

##### 题目描述

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

##### 输入

输入为一行，其中运算符和运算数之间都用空格分隔，运算数是浮点数。

##### 输出

输出为一行，表达式的值，保留 `6` 位小数。

##### 样例输入

```text
* + 11.0 12.0 + 24.0 35.0
```

##### 样例输出

```text
1357.000000
```

##### 解题思路

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

##### 最终代码

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

#### G. 合并队列

##### 题目描述

上体育课的时候，老师已经把班级同学排成了两个队列，而且每个队列都是按照从低到高排好队。

现在需要把两个队列合并，合并后需要保证还是从低到高排列。

请编程实现合并队列。

##### 输入

第 `1` 行为 `n`，表示开始排成的每个队列的长度。

第 `2、3` 行分别是代表从小到大的 `n` 个整数，每行的整数之间用一个空格间隔。

##### 输出

输出占一行，为从小到大的整数，每个整数之间间隔一个空格。

##### 样例输入

```text
5
1 3 5 8 15
2 3 4 6 9
```

##### 样例输出

```text
1 2 3 3 4 5 6 8 9 15
```

##### 解题思路

因为两个队列本来就是从小到大排列的，所以不需要重新排序。

每次只需要比较两个队首元素：

```text
a.front()
b.front()
```

哪个小，就先输出哪个，并让它出队。

如果一个队列已经为空，就直接输出另一个队列剩下的所有元素。

##### 最终代码

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

### 实践二

#### A. 子串个数

##### 题目描述

给你若干个字符串，请编程输出每个字符串的子串个数。

字符串中不含空格，长度最大为 `1000`。

##### 输入

输入包含若干个字符串。

每个字符串占一行。

##### 输出

对应每一行的字符串，输出该字符串子串的个数。

##### 样例输入

```text
abc
apple
software
```

##### 样例输出

```text
7
16
37
```

##### 解题思路

一个长度为 `n` 的字符串，非空连续子串的个数为：

```text
n * (n + 1) / 2
```

例如长度为 `3` 的字符串 `abc`，非空子串有 `6` 个

但是样例中 `abc` 的答案是 `7`，说明本题把空串也算作一个子串，所以最终答案为：

```text
n * (n + 1) / 2 + 1
```

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
int main() {
    string s;
    while (cin >> s) {
        int n = s.size();
        cout << n * (n + 1) / 2 + 1 << endl;
    }
    return 0;
}
```

---

#### B. 模式串

##### 题目描述

给你一个目标串，请查找在目标串中是否存在模式串。

如果存在，就输出第一个模式串在目标串中出现的位置。

##### 输入

输入占两行。

第一行是目标串，长度小于 `1000`。

第二行是模式串，长度小于 `100`。

##### 输出

输出模式串在目标串中出现的位置，即模式串匹配到目标串时第一个字符在目标串中的位置。

注意位置从 `1` 开始。

如果不能匹配，输出 `0`。

##### 样例输入

```text
appleorange
orange
```

##### 样例输出

```text
6
```

##### 解题思路

本题可以使用朴素字符串匹配

从目标串的每一个位置开始，依次和模式串中的字符进行比较

如果模式串的所有字符都能匹配成功，就说明找到了第一次出现的位置，输出当前下标加 `1`

如果所有位置都尝试后仍然无法匹配，则输出 `0`

因为目标串长度小于 `1000`，模式串长度小于 `100`，朴素匹配的复杂度完全可以通过。

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
int main() {
    string s, p;
    cin >> s >> p;
    int ans = 0;
    for (int i = 0; i + p.size() <= s.size(); ++i) {
        int flag = 1;
        for (int j = 0; j < p.size(); ++j) {
            if (s[i + j] != p[j]) {
                flag = 0;
                break;
            }
        }
        if (flag) {
            ans = i + 1;
            break;
        }
    }
    cout << ans << endl;
    return 0;
}
```

---

#### C. 主对角线上的数据和

##### 题目描述

在一个 `N` 行 `N` 列的方阵中，从左上角到右下角这一斜线上有 `N` 个数据元素。

这个斜线称为方阵的主对角线。

给你一个方阵，请求方阵主对角线上数据的和。

##### 输入

第一行是 `N`，表示下面是一个 `N` 阶方阵。

接下来 `N` 行，每行有 `N` 个用空格隔开的正整数。

##### 输出

输出 `N` 阶方阵主对角线上数据的和。

##### 样例输入

```text
3
1 2 3
1 2 3
1 2 3
```

##### 样例输出

```text
6
```

##### 解题思路

主对角线上的元素满足行号和列号相同

如果用 `i` 表示行号，`j` 表示列号，那么主对角线元素满足：

```text
i == j
```

因此读入整个矩阵时，只需要把 `i == j` 的元素累加到答案中即可

##### 最终代码

```cpp
#include <iostream>
using namespace std;
int main() {
    int n;
    cin >> n;
    int ans = 0;
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            int x;
            cin >> x;
            if (i == j) {
                ans += x;
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```

---

#### D. 顺时针排螺旋阵

##### 题目描述

给你一个 `N` 行 `N` 列的方格矩阵，从外圈按顺时针依次填写自然数。

这会构成一个螺旋阵，请编程实现。

##### 输入

输入一个正整数 `N`。

其中 `N < 100`。

##### 输出

输出符合题意的螺旋阵。

##### 样例输入

```text
5
```

##### 样例输出

```text
1 2 3 4 5
16 17 18 19 6
15 24 25 20 7
14 23 22 21 8
13 12 11 10 9
```

##### 解题思路

螺旋阵的填写顺序可以看成四个方向不断循环：

```text
右、下、左、上
```

用两个方向数组表示每次移动时行和列的变化：

```text
dx = {0, 1, 0, -1}
dy = {1, 0, -1, 0}
```

从左上角开始填入 `1`，每次尝试向当前方向走一步

如果下一步越界，或者下一步的位置已经填过数字，就改变方向

一直填到 `n * n` 为止

##### 最终代码

```cpp
#include <iostream>
using namespace std;
int main() {
    int n;
    cin >> n;
    int a[105][105] = {};
    int dx[4] = {0, 1, 0, -1};
    int dy[4] = {1, 0, -1, 0};
    int x = 0, y = 0, d = 0;
    for (int i = 1; i <= n * n; ++i) {
        a[x][y] = i;
        int nx = x + dx[d];
        int ny = y + dy[d];
        if (nx < 0 || nx >= n || ny < 0 || ny >= n || a[nx][ny] != 0) {
            d = (d + 1) % 4;
            nx = x + dx[d];
            ny = y + dy[d];
        }
        x = nx;
        y = ny;
    }
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            if (j) {
                cout << " ";
            }
            cout << a[i][j];
        }
        cout << endl;
    }
    return 0;
}
```

---

#### E. 汉诺塔游戏中的移动

##### 题目描述

有三根标为 `A`、`B`、`C` 的柱子。

`A` 柱子上从上到下按金字塔状依次叠放着 `n` 个半径从 `1` 厘米到 `n` 厘米的圆盘。

要求把 `A` 上的所有盘子移动到柱子 `C` 上，中间可以临时放在 `B` 上。

每次移动时，每一根柱子上都不能出现大盘子在小盘子上方的情况。

请用最少的移动次数完成，并输出每次移动过程。

##### 输入

输入一行整数 `n`，表示盘子数。

其中 `n < 64`。

##### 输出

把 `A` 上的所有盘子移动到柱子 `C` 上，每次只能移动一个盘子。

每次移动占一行。

每行第一个数表示第几步移动，第二个数表示移动的盘子的半径，然后输出从哪个柱子移动到哪个柱子。

##### 样例输入

```text
2
```

##### 样例输出

```text
1 1 A->B
2 2 A->C
3 1 B->C
```

##### 解题思路

汉诺塔递归问题

要把 `n` 个盘子从 `A` 移到 `C`，可以分成三步：

```text
1. 先把上面的 n - 1 个盘子从 A 移到 B
2. 把第 n 个盘子从 A 移到 C
3. 再把 n - 1 个盘子从 B 移到 C
```

递归函数可以设计为：

```text
hanoi(n, a, b, c)
```

表示借助柱子 `b`，把 `n` 个盘子从柱子 `a` 移到柱子 `c`

每移动一次，就让步数加 `1` 并输出当前移动过程

##### 最终代码

```cpp
#include <iostream>
using namespace std;
#define int long long
int cnt = 0;
void hanoi(int n, char a, char b, char c) {
    if (n == 0) {
        return;
    }
    hanoi(n - 1, a, c, b);
    cout << ++cnt << " " << n << " " << a << "->" << c << endl;
    hanoi(n - 1, b, a, c);
}
signed main() {
    int n;
    cin >> n;
    hanoi(n, 'A', 'B', 'C');
    return 0;
}
```

---

#### F. 树的先根遍历

##### 题目描述

已知一棵树的节点间关系，请编程实现该树的先根遍历。

每个节点用不同的大写字母表示，节点数小于 `26`，且树的度小于 `5`。

##### 输入

输入包含若干行。

每行描述一组双亲节点和孩子节点的关系序偶对。

##### 输出

输出该树的先根遍历序列，序列中每个字母用空格隔开。

##### 样例输入

```text
B E
B F
A B
A C
```

##### 样例输出

```text
A B E F C
```

##### 解题思路

先根遍历的顺序是：

```text
先访问根节点，再从左到右访问每一棵子树
```

输入给出的是父子关系。

可以用邻接表 `g` 保存每个节点的孩子节点，并用 `hasfa` 标记某个节点是否有父亲

读入结束后，没有父亲的节点就是根节点

找到根节点之后进行深度优先搜索，进入一个节点时先把它加入答案，再递归遍历它的孩子

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
vector<int> g[26];
int vis[26], hasfa[26];
vector<char> ans;
void dfs(int u) {
    ans.push_back(char(u + 'A'));
    for (int i = 0; i < g[u].size(); ++i) {
        dfs(g[u][i]);
    }
}
int main() {
    char a, b;
    while (cin >> a >> b) {
        int x = a - 'A';
        int y = b - 'A';
        g[x].push_back(y);
        vis[x] = vis[y] = 1;
        hasfa[y] = 1;
    }
    int root = -1;
    for (int i = 0; i < 26; ++i) {
        if (vis[i] && !hasfa[i]) {
            root = i;
            break;
        }
    }
    if (root != -1) {
        dfs(root);
    }
    for (int i = 0; i < ans.size(); ++i) {
        if (i) {
            cout << " ";
        }
        cout << ans[i];
    }
    cout << endl;
    return 0;
}
```

---

#### G. 树的后根遍历

##### 题目描述

已知一棵树的节点间关系，请编程实现该树的后根遍历序列。

每个节点用不同的大写字母表示，节点数小于 `26`，且树的度小于 `5`。

##### 输入

输入包含若干行。

每行描述一组双亲节点和孩子节点的关系序偶对。

##### 输出

输出该树的后根遍历序列，序列中每个字母用空格隔开。

##### 样例输入

```text
B E
B F
A B
A C
```

##### 样例输出

```text
E F B C A
```

##### 解题思路

后根遍历的顺序是：

```text
先从左到右访问每一棵子树，最后访问根节点
```

建树方式和 F 题相同

用邻接表保存孩子节点，用 `hasfa` 标记节点是否有父亲

读入完成后，没有父亲的节点就是根节点

进行深度优先搜索时，先递归访问所有孩子，最后再把当前节点加入答案

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
vector<int> g[26];
int vis[26], hasfa[26];
vector<char> ans;
void dfs(int u) {
    for (int i = 0; i < g[u].size(); ++i) {
        dfs(g[u][i]);
    }
    ans.push_back(char(u + 'A'));
}
int main() {
    char a, b;
    while (cin >> a >> b) {
        int x = a - 'A';
        int y = b - 'A';
        g[x].push_back(y);
        vis[x] = vis[y] = 1;
        hasfa[y] = 1;
    }
    int root = -1;
    for (int i = 0; i < 26; ++i) {
        if (vis[i] && !hasfa[i]) {
            root = i;
            break;
        }
    }
    if (root != -1) {
        dfs(root);
    }
    for (int i = 0; i < ans.size(); ++i) {
        if (i) {
            cout << " ";
        }
        cout << ans[i];
    }
    cout << endl;
    return 0;
}
```

### 实践三

#### A. 二叉链表存储的二叉树

##### 题目描述

给出一个按照先序遍历得到的字符串，其中空格表示空子节点，大写字母表示非空节点。

要求根据这个字符串建立二叉树，并分别输出：

1. 先序遍历结果
2. 第一种非递归中序遍历结果
3. 第二种非递归中序遍历结果

每个非空节点后面输出一个空格。

##### 输入

输入只有一行，包含一个字符串 `S`。

字符串中空格代表空节点，大写字母代表节点内容，长度不超过 `100`。

##### 输出

输出三行。

第一行为先序遍历序列。

第二行为第一种中序遍历序列。

第三行为第二种中序遍历序列。

##### 样例输入

```text
ABC  DE G  F   
```

##### 样例输出

```text
A B C D E G F 
C B E G D F A 
C B E G D F A 
```

##### 解题思路

因为输入字符串本身就是带空节点标记的先序序列，所以可以按照先序递归建树：

1. 如果当前字符是空格，说明当前位置是空子树
2. 如果当前字符是大写字母，就新建节点
3. 递归建立左子树
4. 递归建立右子树

建树完成后，先序遍历可以直接递归输出。

中序遍历使用两种非递归写法，核心都借助栈模拟递归过程。

本题要特别注意：输入中的空格是有效字符，不能用 `cin >> s`，应该用 `getline(cin, s)` 读取整行。

##### 最终代码

```cpp
#include <iostream>
#include <string>
#include <stack>
using namespace std;
struct BiTNode {
    char data;
    BiTNode *lchild, *rchild;
};
string s;
int pos = 0;
BiTNode* create() {
    if (pos >= s.size()) {
        return NULL;
    }
    char ch = s[pos++];
    if (ch == ' ') {
        return NULL;
    }
    BiTNode* t = new BiTNode;
    t->data = ch;
    t->lchild = create();
    t->rchild = create();
    return t;
}
void preorder(BiTNode* t) {
    if (t) {
        cout << t->data << " ";
        preorder(t->lchild);
        preorder(t->rchild);
    }
}
void inorder1(BiTNode* t) {
    stack<BiTNode*> st;
    while (t || !st.empty()) {
        if (t) {
            st.push(t);
            t = t->lchild;
        } else {
            t = st.top();
            st.pop();
            cout << t->data << " ";
            t = t->rchild;
        }
    }
}
void inorder2(BiTNode* t) {
    stack<BiTNode*> st;
    st.push(t);
    while (!st.empty()) {
        while (st.top()) {
            st.push(st.top()->lchild);
        }
        st.pop();
        if (!st.empty()) {
            t = st.top();
            st.pop();
            cout << t->data << " ";
            st.push(t->rchild);
        }
    }
}
int main() {
    getline(cin, s);
    BiTNode* t = create();
    preorder(t);
    cout << endl;
    inorder1(t);
    cout << endl;
    inorder2(t);
    cout << endl;
    return 0;
}
```

---

#### B. 哈夫曼树

##### 题目描述

第一行输入一个数 `n`，表示叶节点的个数。

接着输入 `n` 个叶节点的权值，需要用这些叶节点生成哈夫曼树，并输出所有叶子节点的路径长度与权值乘积之和，也就是哈夫曼树的带权路径长度。

##### 输入

输入包含多组数据。

每组第一行输入一个数 `n`，接着输入 `n` 个叶节点权值。

其中 `2 <= n <= 1000`，叶节点权值不超过 `100`。

##### 输出

对于每组数据，输出哈夫曼树的带权路径长度。

##### 样例输入

```text
2
2 8
3
5 11 30
```

##### 样例输出

```text
10
62
```

##### 解题思路

哈夫曼树的构造规则是：每次选取权值最小的两个节点合并。

合并出的新节点权值为两个节点权值之和，并重新放回集合中。

在这个过程中，每一次合并产生的代价都会计入最终答案。

因此可以使用小根堆维护当前所有节点权值：

1. 将所有叶节点权值加入小根堆
2. 每次取出两个最小值 `a` 和 `b`
3. 将 `a + b` 加到答案中
4. 再把 `a + b` 放回堆中
5. 堆中只剩一个节点时结束

##### 最终代码

```cpp
#include <iostream>
#include <queue>
#include <vector>
using namespace std;
int main() {
    int n;
    while (cin >> n) {
        priority_queue<int, vector<int>, greater<int> > q;
        for (int i = 0; i < n; ++i) {
            int x;
            cin >> x;
            q.push(x);
        }
        int ans = 0;
        while (q.size() > 1) {
            int a = q.top();
            q.pop();
            int b = q.top();
            q.pop();
            ans += a + b;
            q.push(a + b);
        }
        cout << ans << endl;
    }
    return 0;
}
```

---

#### C. 树的遍历

##### 题目描述

已知二叉树中所有键值都是不同的正整数。

如果给出前序遍历和中序遍历，或者给出后序遍历和中序遍历，都可以唯一确定一棵二叉树。

但是如果只给出前序遍历和后序遍历，二叉树不一定唯一。

现在给出一棵二叉树的前序序列和后序序列，要求输出一组可行的中序遍历序列。

如果这棵树唯一，输出 `Yes`；否则输出 `No`。

##### 输入

第一行输入正整数 `N`，表示二叉树中的节点总数。

第二行输入前序遍历序列。

第三行输入后序遍历序列。

##### 输出

第一行输出 `Yes` 或 `No`。

如果树唯一，输出 `Yes`；否则输出 `No`。

第二行输出对应的中序遍历序列，数字之间用一个空格隔开，行尾不能有多余空格。

##### 样例输入

```text
7
1 2 3 4 6 7 5
2 6 7 4 5 3 1
```

##### 样例输出

```text
Yes
2 1 6 4 7 3 5
```

##### 解题思路

前序遍历的第一个节点一定是当前子树的根。

后序遍历的最后一个节点也一定是当前子树的根。

在当前区间中，如果节点数大于 `1`，那么后序序列中根节点前面的那个节点可以看作右子树的根。

找到这个右子树根在前序序列中的位置，就可以把前序序列分成左子树和右子树两部分。

如果当前根节点下面只有一棵子树，那么这棵子树既可以看作左子树，也可以看作右子树，因此二叉树不唯一。

递归过程中按照：

```text
左子树 -> 根节点 -> 右子树
```

把节点加入答案，就能得到一组合法的中序遍历序列。

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
vector<int> pre, post, in;
bool flag = true;
void dfs(int pl, int pr, int pol, int por) {
    if (pl > pr) return;
    if (pl == pr) {
        in.push_back(pre[pl]);
        return;
    }
    int rightRoot = post[por - 1], k = pl;
    while (pre[k] != rightRoot) k++;
    int rightSize = pr - k + 1;
    if (rightSize == pr - pl) flag = false;
    dfs(pl + 1, k - 1, pol, por - rightSize - 1);
    in.push_back(pre[pl]);
    dfs(k, pr, por - rightSize, por - 1);
}
int main() {
    int n;
    cin >> n;
    pre.resize(n), post.resize(n);
    for (int i = 0; i < n; ++i) cin >> pre[i];
    for (int i = 0; i < n; ++i) cin >> post[i];
    dfs(0, n - 1, 0, n - 1);
    cout << (flag ? "Yes" : "No") << endl;
    for (int i = 0; i < n; ++i) {
        if (i) cout << " ";
        cout << in[i];
    }
    cout << endl;
    return 0;
}
```

---

#### D. 最短路径

##### 题目描述

一个迷宫地图中，多个房间由单向通道相连。

房间号从 `1` 到 `N` 依次编号。

给出所有单向通道及其长度，求起点房间到终点房间之间的最短路径长度。

##### 输入

第一行输入房间数 `N` 和单向通道数 `M`。

接下来 `M` 行，每行输入三个整数 `x y z`，表示存在一条从 `x` 到 `y` 的单向通道，长度为 `z`。

最后一行输入 `start` 和 `end`，表示起点和终点。

##### 输出

输出起点房间到终点房间的最短路径长度。

如果没有通路，输出 `STOP`。

##### 样例输入

```text
7 9
1 2 3
1 3 2
3 4 2
6 3 1
2 6 3
6 7 6
2 5 4
5 4 2
5 7 5
1 7
```

##### 样例输出

```text
12
```

##### 解题思路

本题是带正权边的单源最短路径问题。

因为通道长度都是正数，所以可以使用 Dijkstra 算法。

用邻接表保存有向边，`dis[i]` 表示从起点到房间 `i` 的当前最短距离。

再用小根堆每次取出当前距离最小的房间进行松弛：

```text
if (dis[v] > dis[u] + w)
    dis[v] = dis[u] + w
```

最后如果终点距离仍然是无穷大，说明无法到达，输出 `STOP`。

##### 最终代码

```cpp
#include <iostream>
#include <queue>
#include <vector>
using namespace std;
struct Edge {
    int to;
    int w;
};
const int INF = 114514;
int main() {
    int n, m;
    cin >> n >> m;
    vector<Edge> g[105];
    for (int i = 0; i < m; ++i) {
        int x, y, z;
        cin >> x >> y >> z;
        g[x].push_back({y, z});
    }
    int start, end;
    cin >> start >> end;
    vector<int> dis(n + 1, INF);
    vector<int> vis(n + 1, 0);
    priority_queue<
        pair<int, int>,
        vector<pair<int, int> >,
        greater<pair<int, int> >
    > q;
    dis[start] = 0;
    q.push({0, start});
    while (!q.empty()) {
        int u = q.top().second;
        q.pop();

        if (vis[u]) {
            continue;
        }
        vis[u] = 1;
        for (int i = 0; i < g[u].size(); ++i) {
            int v = g[u][i].to;
            int w = g[u][i].w;

            if (dis[v] > dis[u] + w) {
                dis[v] = dis[u] + w;
                q.push({dis[v], v});
            }
        }
    }
    if (dis[end] == INF) {
        cout << "STOP" << endl;
    } else {
        cout << dis[end] << endl;
    }
    return 0;
}
```

---

#### E. 最小生成树

##### 题目描述

给出一个无向图的邻接矩阵。

矩阵中第 `i` 行第 `j` 个数如果不为 `0`，表示第 `i` 个顶点和第 `j` 个顶点之间有直接连接，且代价为该数。

`0` 表示没有直接连接。

要求使用最小生成树思想，输出连接所有顶点所需要的最小总代价。

##### 输入

第一行输入正整数 `n`，表示图中共有 `n` 个顶点。

接下来 `n` 行，每行输入 `n` 个整数，表示无向图的邻接矩阵。

输入保证矩阵对称，并且图只有一个连通分量。

##### 输出

输出一个整数，表示最小生成树的总代价。

##### 样例输入

```text
4
0 2 4 0
2 0 3 5
4 3 0 1
0 5 1 0
```

##### 样例输出

```text
6
```

##### 解题思路

本题使用 Prim 算法。

先从 `1` 号顶点开始，把它加入生成树集合。

`lowcost[i]` 表示当前生成树集合连接到顶点 `i` 的最小边权。

每一轮选择一个未加入生成树、且 `lowcost` 最小的顶点加入答案，然后用这个新加入的顶点更新其他顶点的 `lowcost`。

因为题目保证图连通，所以最终一定能加入所有顶点。

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
int main() {
    int n;
    cin >> n;
    vector<vector<int> > a(n + 1, vector<int>(n + 1));
    for (int i = 1; i <= n; ++i) {
        for (int j = 1; j <= n; ++j) {
            cin >> a[i][j];
        }
    }
    vector<int> lowcost(n + 1, -1);
    vector<int> vis(n + 1, 0);
    vis[1] = 1;
    for (int i = 1; i <= n; ++i) {
        if (a[1][i] != 0) {
            lowcost[i] = a[1][i];
        }
    }
    int ans = 0;
    for (int i = 1; i < n; ++i) {
        int k = 0;

        for (int j = 1; j <= n; ++j) {
            if (!vis[j] && lowcost[j] != -1) {
                if (k == 0 || lowcost[j] < lowcost[k]) {
                    k = j;
                }
            }
        }
        vis[k] = 1;
        ans += lowcost[k];
        for (int j = 1; j <= n; ++j) {
            if (!vis[j] && a[k][j] != 0) {
                if (lowcost[j] == -1 || lowcost[j] > a[k][j]) {
                    lowcost[j] = a[k][j];
                }
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```

### 实践四

#### A. 机器人王国里的路径长度

##### 题目描述

机器人王国以首都为根节点，向外分层建设卫星城市。

每个城市会向下一层分出两个卫星城，每条道路长度不同。第 `N` 层的卫星城不再继续分出新的城市。

现在给出所有直接相连城市之间的道路长度，要求计算某个卫星城到首都的路程。

##### 输入

第一行输入 `N`，表示有 `N` 层卫星城。

接下来输入 `2^(N+1)-2` 行，每行包含父城市代号、子城市代号和它们之间的路程。

最后一行输入要求查询的卫星城代号。

##### 输出

输出该卫星城到首都的路程。

##### 样例输入

```text
2
A F 20
B D 100
G A 5
G B 10
A C 6
B E 30
D
```

##### 样例输出

```text
110
```

##### 解题思路

输入给出的边是父城市到子城市的路程。

要求某个卫星城到首都的距离，可以反过来存每个子城市的父亲：

```text
fa[child] = parent
len[child] = distance
```

最后从查询城市开始，不断向父亲走，每走一条边就把边长加到答案中，直到走到没有父亲的城市，也就是首都。

##### 最终代码

```cpp
#include <iostream>
#include <map>
#include <string>
using namespace std;
int main() {
    int n;
    cin >> n;
    map<string, string> fa;
    map<string, int> len;
    int m = (1 << (n + 1)) - 2;
    for (int i = 0; i < m; ++i) {
        string a, b;
        int w;
        cin >> a >> b >> w;
        fa[b] = a;
        len[b] = w;
    }
    string s;
    cin >> s;
    int ans = 0;
    while (fa.count(s)) {
        ans += len[s];
        s = fa[s];
    }
    cout << ans << endl;
    return 0;
}
```

---

#### B. 从源点开始的最短路径

##### 题目描述

给出一个有向图的所有有序边，顶点用 `1` 到 `n` 编号。

要求求出从源点 `1` 到指定顶点 `i` 的最短路径长度。

##### 输入

第一行输入 `n` 和 `m`，分别表示顶点数和有向边数。

接下来 `m` 行，每行输入三个数，前两个数表示一条有向边，第三个数表示边权。

最后一行输入目标顶点 `i`。

##### 输出

输出从 `1` 到顶点 `i` 的最短路径长度。

##### 样例输入

```text
4 5
1 2 4
1 3 6
2 3 1
3 4 6
2 4 7
3
```

##### 样例输出

```text
5
```

##### 解题思路

本题是单源最短路径问题，源点固定为 `1`。

因为边权为正，可以使用 Dijkstra 算法。

用邻接表保存有向边，`dis[v]` 表示从 `1` 到顶点 `v` 的当前最短距离。

每次从小根堆中取出距离最小的顶点进行松弛，最后输出 `dis[end]`。

##### 最终代码

```cpp
#include <iostream>
#include <queue>
#include <vector>
using namespace std;
struct Edge {
    int to;
    int w;
};
const int INF = 114514;
int main() {
    int n, m;
    cin >> n >> m;
    vector<Edge> g[105];
    for (int i = 0; i < m; ++i) {
        int x, y, z;
        cin >> x >> y >> z;
        g[x].push_back({y, z});
    }
    int end;
    cin >> end;
    vector<int> dis(n + 1, INF);
    vector<int> vis(n + 1, 0);
    priority_queue<
        pair<int, int>,
        vector<pair<int, int> >,
        greater<pair<int, int> >
    > q;
    dis[1] = 0;
    q.push({0, 1});
    while (!q.empty()) {
        int u = q.top().second;
        q.pop();
        if (vis[u]) {
            continue;
        }
        vis[u] = 1;
        for (int i = 0; i < g[u].size(); ++i) {
            int v = g[u][i].to;
            int w = g[u][i].w;
            if (dis[v] > dis[u] + w) {
                dis[v] = dis[u] + w;
                q.push({dis[v], v});
            }
        }
    }
    cout << dis[end] << endl;
    return 0;
}
```

---

#### C. 最少天数

##### 题目描述

一项工程由许多有前后依赖关系的子任务组成。

每个子任务用一个开始事件和结束事件表示，并给出完成该子任务需要的天数。

整个工程的开始事件为 `A`，结束事件为 `Z`。

要求计算完成整个工程所需的最少天数。

##### 输入

第一行输入事件节点个数 `N` 和子任务数 `M`。

接下来 `M` 行，每行输入子任务的开始事件、结束事件以及完成该任务所需天数。

##### 输出

输出完成该工程所需的最少天数。

##### 样例输入

```text
4 3
A B 6
B Z 2
A Z 5
```

##### 样例输出

```text
8
```

##### 解题思路

这题不能按普通最短路理解。

样例中虽然 `A -> Z` 直接路径长度为 `5`，但还有任务链 `A -> B -> Z`，需要 `6 + 2 = 8` 天。

工程必须等所有依赖任务完成后才能结束，所以总工期取决于关键路径，也就是从 `A` 到 `Z` 的最长路径。

因此可以在有向无环图上做记忆化搜索：

```text
dfs(u) = 从事件 u 到 Z 还需要的最长时间
```

答案就是 `dfs(A)`。

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
struct Edge {
    int to;
    int w;
};
vector<Edge> g[26];
int dp[26], vis[26];
int dfs(int u) {
    if (u == 'Z' - 'A') {
        return 0;
    }
    if (vis[u]) {
        return dp[u];
    }
    vis[u] = 1;
    for (int i = 0; i < g[u].size(); ++i) {
        int v = g[u][i].to;
        int w = g[u][i].w;
        dp[u] = max(dp[u], dfs(v) + w);
    }
    return dp[u];
}
int main() {
    int n, m;
    cin >> n >> m;
    for (int i = 0; i < m; ++i) {
        char a, b;
        int w;
        cin >> a >> b >> w;
        g[a - 'A'].push_back({b - 'A', w});
    }
    cout << dfs(0) << endl;
    return 0;
}
```

---

#### D. 寻找第二小的数

##### 题目描述

求 `n` 个整数中第二小的数。

相同的整数看成一个数。

例如 `1 1 3 4 5` 中，第二小的数是 `3`。

##### 输入

第一行输入整数 `C`，表示有 `C` 组测试数据。

每组数据第一行输入 `n`，表示本组有 `n` 个整数。

接着一行输入 `n` 个整数。

##### 输出

对每组测试数据输出第二小的整数。

如果不存在第二小的整数，输出 `NO`。

##### 样例输入

```text
3
2
1 2
5
1 1 3 4 5
3
1 1 1
```

##### 样例输出

```text
2
3
NO
```

##### 解题思路

先把数组从小到大排序。

排序后，最小值一定是 `a[0]`。

从 `a[1]` 开始向后找第一个不等于 `a[0]` 的数，它就是第二小的不同整数。

如果找不到，说明所有数都相同，不存在第二小的数。

##### 最终代码

```cpp
#include <iostream>
#include <algorithm>
using namespace std;
int main() {
    int c;
    cin >> c;
    while (c--) {
        int n;
        cin >> n;
        int a[15];
        for (int i = 0; i < n; ++i) {
            cin >> a[i];
        }
        sort(a, a + n);
        int ans = -1;
        for (int i = 1; i < n; ++i) {
            if (a[i] != a[0]) {
                ans = a[i];
                break;
            }
        }
        if (ans == -1) {
            cout << "NO" << endl;
        } else {
            cout << ans << endl;
        }
    }
    return 0;
}
```

---

#### E. 按十进制各位和排序

##### 题目描述

对于给定的正整数序列，按照每个数十进制形式各位数字之和从大到小排序。

如果各位数字之和相同，则按照数字本身大小从大到小排序。

##### 输入

第一行输入整数 `n`，表示序列大小。

第二行输入 `n` 个正整数。

##### 输出

输出按照题目要求排序后的序列。

##### 样例输入

```text
6
17 26 9 13 88 22
```

##### 样例输出

```text
88 9 26 17 22 13
```

##### 解题思路

先写一个函数求一个整数的十进制各位数字之和。

排序时使用自定义比较函数：

1. 如果两个数的数位和不同，数位和大的排前面
2. 如果两个数的数位和相同，数字本身大的排前面

##### 最终代码

```cpp
#include <iostream>
#include <algorithm>
using namespace std;
int sum(int x) {
    int ans = 0;
    while (x) {
        ans += x % 10;
        x /= 10;
    }
    return ans;
}
bool cmp(int a, int b) {
    int sa = sum(a);
    int sb = sum(b);
    if (sa != sb) {
        return sa > sb;
    }
    return a > b;
}
int main() {
    int n;
    cin >> n;
    int a[1005];
    for (int i = 0; i < n; ++i) {
        cin >> a[i];
    }
    sort(a, a + n, cmp);
    for (int i = 0; i < n; ++i) {
        if (i) {
            cout << " ";
        }
        cout << a[i];
    }
    cout << endl;
    return 0;
}
```

---

#### F. 奇偶数的排序

##### 题目描述

给你 `10` 个正整数，其中有 `5` 个奇数和 `5` 个偶数。

要求先把奇数按从大到小排序输出，然后再把偶数按从小到大排序输出。

##### 输入

输入一行 `10` 个正整数。

##### 输出

先递减输出 `5` 个奇数，再递增输出 `5` 个偶数。

各个数之间用一个空格隔开。

##### 样例输入

```text
1 2 3 4 5 6 7 8 10 9
```

##### 样例输出

```text
9 7 5 3 1 2 4 6 8 10
```

##### 解题思路

可以直接写一个自定义比较函数：

1. 如果一个数是奇数，另一个数是偶数，奇数排在前面
2. 如果两个数都是奇数，数值大的排在前面
3. 如果两个数都是偶数，数值小的排在前面

然后直接对整个数组排序即可。

##### 最终代码

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
bool cmp(int a, int b) {
    bool m = (a % 2 != 0);
    bool n = (b % 2 != 0);
    if (m && !n) return true;  
    if (!m && n) return false;  
    if (m) return a > b;           
    else       return a < b;          
}

int main() {
    const int n = 10;                 
    vector<int> arr(n);
    for (int i = 0; i < n; ++i) {
        cin >> arr[i];        
    }
    sort(arr.begin(), arr.end(), cmp);
    for (int i = 0; i < n; ++i) {
        if (i) {
            cout << " ";
        }
        cout << arr[i];
    }
    cout << endl;
    return 0;
}
```

---


---

## 数据结构作业

### 作业一

#### A. 查成绩

##### 题目描述

期末考试结束后，数学老师给出了班里同学们的数学成绩，为了快速查成绩，请编程帮助查成绩。

##### 输入

第一行为 `N`，`N < 1000`，表示班级人数。

第一行后有 `N` 行，每行两个部分，一个是学号，一个是成绩。

最后一行是要查找成绩同学的学号。

##### 输出

输出要查找同学的成绩。

##### 样例输入

```text
2
001 90
002 95
002
```

##### 样例输出

```text
95
```

##### 解题思路

用两个数组分别保存学号和成绩。读入要查询的学号后，从前往后顺序查找，如果当前学号和目标学号相同，就输出对应的成绩并结束。

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
int main(){
    int N;
    cin >> N;
    string id[1000];
    int score[1000];
    for(int i = 0; i < N; i++)
        cin >> id[i] >> score[i];
    string ids;
    cin >> ids;
    for(int i = 0; i < N; i++)
        if(ids == id[i]){
            cout << score[i] << endl;
            break;
        }
    return 0;
}
```

---

#### B. 插入数据

##### 题目描述

已有一个整数序列，现在要在不同的位置插入一些整数，请输出插入数据后的序列。

##### 输入

第一行是 `N`，`N < 1000`，表示原序列中元素的个数。

第二行是 `N` 个整数。

第三行是要插入的元素个数 `M`，`M < 1000`。

第四行开始有 `M` 行，每行是一对数据 `k` 和 `x`，表示要在原序列第 `k` 个位置插入整数 `x`。

##### 输出

输出插入元素后的整数序列。

##### 样例输入

```text
5
1 2 3 4 5
2
1 11
3 33
```

##### 样例输出

```text
11 1 2 33 3 4 5
```

##### 解题思路

使用 `vector` 保存原整数序列。每次插入时使用 `insert` 函数。

因为题目给出的 `k` 是相对于原序列的位置，而前面已经插入了 `i` 个元素，所以第 `i` 次插入时，实际插入位置为：

```text
k - 1 + i
```

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
int main(){
    int N;
    cin >> N;
    vector<int> num(N);
    for(int i = 0; i < N; i++)
        cin >> num[i];
    int M;
    cin >> M;
    for(int i = 0; i < M; i++){
        int k,x;
        cin >> k >> x;
        num.insert(num.begin() + k - 1 + i, x);
    }
    int len = num.size();
    for(int i = 0; i < len; i++)
        cout << num[i] << (i + 1 < len ? " " : "\n");
    return 0;
}
```

---

#### C. 二路归并

##### 题目描述

有两个按元素值递增有序的整数顺序表 `A` 和 `B`，设计一个算法将顺序表 `A` 和 `B` 的全部元素合并到一个递增有序顺序表 `C` 中，并依次输出 `C` 中的元素。

##### 输入

输入占两行，依次是 `A` 和 `B` 的序列，元素个数都小于 `100`。

##### 输出

依次输出 `C` 中的元素。

##### 样例输入

```text
1 2 3 4 5
1 2 3 4 6
```

##### 样例输出

```text
1 1 2 2 3 3 4 4 5 6
```

##### 解题思路

两个序列本身已经递增有序，所以可以用双指针

令 `i` 指向 `A` 的当前位置，`j` 指向 `B` 的当前位置。每次比较 `A[i]` 和 `B[j]`，把较小的元素放入 `C`。如果其中一个序列已经全部放入 `C`，就把另一个序列剩下的元素全部加入

本题没有给出每行元素个数，所以使用 `getline` 读入整行，再手动扫描字符串得到整数

##### 最终代码

```cpp
#include <iostream>
#include <vector>
#include <string>
using namespace std;
void getnum(string s, vector<int> &num){
    int n = s.length();
    for(int i = 0; i < n; i++){
        if(s[i] == ' ')
            continue;
        int x = 0,flag = 1;
        if(s[i] == '-'){
            flag = -1;
            i++;
        }
        while(i < n && s[i] >= '0' && s[i] <= '9'){
            x = x * 10 + s[i] - '0';
            i++;
        }
        num.push_back(x * flag);
    }
}
int main(){
    string s;
    vector<int> A,B,C;
    getline(cin, s);
    getnum(s, A);
    getline(cin, s);
    getnum(s, B);
    int i = 0,j = 0;
    int n = A.size(),m = B.size();
    while(i < n && j < m){
        if(A[i] <= B[j])
            C.push_back(A[i++]);
        else
            C.push_back(B[j++]);
    }
    while(i < n)
        C.push_back(A[i++]);
    while(j < m)
        C.push_back(B[j++]);
    int k = C.size();
    for(int i = 0; i < k; i++)
        cout << C[i] << (i + 1 < k ? " " : "\n");
    return 0;
}
```

---

#### D. 最大值个数

##### 题目描述

有一个整数单链表 `L`，其中可能存在多个值相同的结点，设计一个算法查找 `L` 中最大值结点的个数。

##### 输入

输入单链表 `L` 中的元素，个数不定。

##### 输出

输出最大值结点的个数。

##### 样例输入

```text
1 2 3 4 5 5 20 20 1 2 3 4 5
```

##### 样例输出

```text
2
```

##### 解题思路

题目描述的是单链表，本质操作就是从头到尾遍历一次

读入过程中维护两个变量：

```text
maxn 表示当前最大值
cnt  表示当前最大值出现次数
```

如果读到的新元素比 `maxn` 大，就更新 `maxn`，并把 `cnt` 重置为 `1`。如果读到的新元素等于 `maxn`，就让 `cnt` 加 `1`

##### 最终代码

```cpp
#include <iostream>
using namespace std;
int main(){
    int x,maxn = 0,cnt = 0;
    bool flag = false;
    while(cin >> x){
        if(!flag || x > maxn){
            maxn = x;
            cnt = 1;
            flag = true;
        }
        else if(x == maxn)
            cnt++;
    }
    cout << cnt << endl;
    return 0;
}
```

---

#### E. 约瑟夫问题

##### 题目描述

有 `n` 个小孩围成一圈，给他们从 `1` 开始依次编号。从编号为 `1` 的小孩开始报数，数到第 `m` 个小孩出列，然后从出列的下一个小孩重新开始报数。如此反复直到所有的小孩全部出列为止，求整个出列序列。

##### 输入

输入占一行，为 `n` 和 `m`，其中 `n < 100`，`0 < m < n`。

##### 输出

输出整个出列序列。

##### 样例输入

```text
6 5
```

##### 样例输出

```text
5 4 6 2 3 1
```

##### 解题思路

用 `vector` 保存当前还在圈中的小孩编号。

设当前报数起点下标为 `k`，当前剩余人数为 `len`，则每次出列的小孩下标为：

```text
k = (k + m - 1) % len
```

删除当前小孩后，`k` 正好指向下一个开始报数的人

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
int main(){
    int n,m;
    cin >> n >> m;
    vector<int> num(n),ans;
    for(int i = 0; i < n; i++)
        num[i] = i + 1;
    int k = 0;
    while(!num.empty()){
        int len = num.size();
        k = (k + m - 1) % len;
        ans.push_back(num[k]);
        num.erase(num.begin() + k);
    }
    for(int i = 0; i < n; i++)
        cout << ans[i] << (i + 1 < n ? " " : "\n");
    return 0;
}
```

---

#### F. 括号配对

##### 题目描述

设计一个算法利用顺序栈检查用户输入的表达式中括号是否配对。假设表达式中可能含有圆括号 `()`、中括号 `[]` 和大括号 `{}`。

##### 输入

输入占一行，为含有三种括号的表达式，最长 `100` 个符号。

##### 输出

匹配时输出 `YES`。

小括号不匹配输出 `NO1`，中括号不匹配输出 `NO2`，大括号不匹配输出 `NO3`。

##### 样例输入

```text
{([a])}
```

##### 样例输出

```text
YES
```

##### 解题思路

使用字符数组模拟顺序栈

遇到左括号时，将它入栈。遇到右括号时，检查栈顶是否是对应的左括号。如果栈为空，或者栈顶括号类型不对应，就说明不匹配，按照当前右括号类型输出对应的 `NO`

扫描结束后，如果栈为空，说明全部括号匹配；如果栈不为空，就根据栈顶剩余的左括号类型输出对应结果

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
void print(char c){
    if(c == '(' || c == ')')
        cout << "NO1" << endl;
    else if(c == '[' || c == ']')
        cout << "NO2" << endl;
    else
        cout << "NO3" << endl;
}
int main(){
    string s;
    getline(cin, s);
    char st[105];
    int top = -1;
    int n = s.length();
    for(int i = 0; i < n; i++){
        if(s[i] == '(' || s[i] == '[' || s[i] == '{')
            st[++top] = s[i];
        else if(s[i] == ')'){
            if(top == -1){
                print(s[i]);
                return 0;
            }
            if(st[top] != '('){
                print(st[top]);
                return 0;
            }
            top--;
        }
        else if(s[i] == ']'){
            if(top == -1){
                print(s[i]);
                return 0;
            }
            if(st[top] != '['){
                print(st[top]);
                return 0;
            }
            top--;
        }
        else if(s[i] == '}'){
            if(top == -1){
                print(s[i]);
                return 0;
            }
            if(st[top] != '{'){
                print(st[top]);
                return 0;
            }
            top--;
        }
    }
    if(top == -1)
        cout << "YES" << endl;
    else
        print(st[top]);
    return 0;
}
```

---

#### G. 后缀表达式

##### 题目描述

给出一个中缀表达式，输出该表达式的后缀表达式。

##### 输入

输入占一行，为一个中缀表达式。运算符只有 `+`、`-`、`*`、`/`，最多 `1000` 个字符。

##### 输出

输出后缀表达式。

##### 样例输入

```text
(56-20)/(4+2)
```

##### 样例输出

```text
56 20 - 4 2 + /
```

##### 解题思路

中缀表达式转后缀表达式可以使用运算符栈

处理规则如下：

1. 如果遇到操作数，直接加入答案
2. 如果遇到左括号，直接入栈
3. 如果遇到右括号，就一直弹出栈顶运算符，直到遇到左括号
4. 如果遇到普通运算符，就弹出栈顶优先级大于等于当前运算符的运算符，然后再把当前运算符入栈
5. 扫描结束后，将栈中剩余运算符依次弹出

样例中有多位数，所以扫描操作数时，需要把连续的数字或字母作为一个整体

##### 最终代码

```cpp
#include <iostream>
#include <string>
#include <vector>
using namespace std;
int priority(char c){
    if(c == '+' || c == '-')
        return 1;
    if(c == '*' || c == '/')
        return 2;
    return 0;
}
bool isop(char c){
    return c == '+' || c == '-' || c == '*' || c == '/';
}
bool isnum(char c){
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
int main(){
    string s;
    getline(cin, s);
    vector<string> ans;
    char st[1005];
    int top = -1;
    int n = s.length();
    for(int i = 0; i < n; i++){
        if(s[i] == ' ')
            continue;
        if(isnum(s[i])){
            string t;
            while(i < n && isnum(s[i])){
                t += s[i];
                i++;
            }
            i--;
            ans.push_back(t);
        }
        else if(s[i] == '(')
            st[++top] = s[i];
        else if(s[i] == ')'){
            while(top != -1 && st[top] != '('){
                string t;
                t += st[top--];
                ans.push_back(t);
            }
            if(top != -1)
                top--;
        }
        else if(isop(s[i])){
            while(top != -1 && st[top] != '(' && priority(st[top]) >= priority(s[i])){
                string t;
                t += st[top--];
                ans.push_back(t);
            }
            st[++top] = s[i];
        }
    }
    while(top != -1){
        if(st[top] != '('){
            string t;
            t += st[top];
            ans.push_back(t);
        }
        top--;
    }
    int k = ans.size();
    for(int i = 0; i < k; i++)
        cout << ans[i] << (i + 1 < k ? " " : "\n");
    return 0;
}
```

---

#### H. 字符串反转

##### 题目描述

小 C 很喜欢倒着写单词。现在给你一行小 C 写的文本，你需要把每个单词都反转并输出。

##### 输入

输入包含多组测试样例。

第一行为一个整数 `T`，代表测试样例的数量，后面跟着 `T` 个测试样例。

每个测试样例占一行，包含多个单词，一行最多有 `1000` 个字符。

##### 输出

对于每一个测试样例，输出转换后的文本。

##### 样例输入

```text
3
olleh !dlrow
I ekil .bulcmca
I evol .mca
```

##### 样例输出

```text
hello world!
I like acmclub.
I love acm.
```

##### 解题思路

逐行读取字符串，使用 `word` 临时保存当前单词

如果当前字符不是空格，就加入 `word`。如果遇到空格，就把 `word` 倒序输出，然后输出空格，并清空 `word`

一行结束后，还需要把最后一个单词倒序输出

标点符号也属于单词的一部分，所以会随着单词一起反转

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
int main(){
    int T;
    cin >> T;
    string s;
    getline(cin, s);
    while(T--){
        getline(cin, s);
        string word;
        int n = s.length();
        for(int i = 0; i < n; i++){
            if(s[i] == ' '){
                int len = word.length();
                for(int j = len - 1; j >= 0; j--)
                    cout << word[j];
                word = "";
                cout << " ";
            }
            else
                word += s[i];
        }
        int len = word.length();
        for(int j = len - 1; j >= 0; j--)
            cout << word[j];
        cout << endl;
    }
    return 0;
}
```
---

### 作业二

#### A. 统计回文子串

##### 题目描述

给定一个字符串 `S`，计算 `S` 中有多少个连续子串是回文串。

##### 输入

输入包含多组测试数据。

每组输入是一个非空字符串，长度不超过 `5000`。

##### 输出

对于每组输入，输出回文子串的个数。

##### 样例输入

```text
aba
aa
```

##### 样例输出

```text
4
3
```

##### 解题思路

回文串可以从中心向两边扩展。

每个字符都可以作为奇数长度回文串的中心，例如 `aba`。

每两个相邻字符中间也可以作为偶数长度回文串的中心，例如 `aa`。

所以对每个位置分别扩展奇数回文和偶数回文，每扩展成功一次，就说明找到了一个回文子串。

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
int main(){
  string s;
  while (cin >> s){
    int n = s.size();
    long long ans = 0;
    for(int i = 0; i < n; i++){
      int l = i, r = i;
      while (l >= 0 && r < n && s[l] == s[r]){
        ans++;
        l--;
        r++;
      }
      l = i;
      r = i + 1;
      while(l >= 0 && r < n && s[l] == s[r]){
        ans++;
        l--;
        r++;
      }
    }
    cout << ans << endl;
  }
  return 0;
}
```

---

#### B. 构建矩阵

##### 题目描述

构建一个 `N * N` 的矩阵。

第 `i` 行第 `j` 列的元素为 `i * j`，其中 `i` 和 `j` 都从 `1` 开始。

##### 输入

第一行输入正整数 `C`，表示测试样例个数。

接下来 `C` 行，每行输入一个整数 `N`。

其中 `1 <= N <= 9`。

##### 输出

对于每组输入，输出构建出的矩阵。

##### 样例输入

```text
2
1
4
```

##### 样例输出

```text
1
1 2 3 4
2 4 6 8
3 6 9 12
4 8 12 16
```

##### 解题思路

矩阵第 `i` 行第 `j` 列的值就是 `i * j`。

因此直接双重循环输出即可。

解法一先把所有测试数据的 `N` 保存下来，再统一输出矩阵。

##### 最终代码：解法一

```cpp
#include <iostream>
using namespace std;
int main(){
  int c;
  cin >> c;
  int b[105];
  for(int i = 1; i <= c; i++){
    cin >> b[i];
  }
  for(int i = 1; i <= c; i++){
    for(int j = 1; j <= b[i]; j++){
      for(int k = 1; k <= b[i]; k++){
        if(k != 1){
          cout << " ";
        }
        cout << j * k;
      }
      cout << endl;
    }
  }
  return 0;
}
```

##### 最终代码：解法二

```cpp
#include <iostream>
using namespace std;
int main(){
  int c;
  cin >> c;
  while(c--){
    int N;
    cin >> N;
    for(int i = 1 ; i <= N; i++){
      for(int j = 1; j <= N; j++){
        cout << i * j;
        if(j != N) cout << " ";
      }
      cout << endl;
    }
  }
  return 0;
}
```

---

#### C. 找规律填数字

##### 题目描述

给出一组有规律序列的前 `5` 个整数，要求输出后面连续的 `5` 个整数。

已知这串序列只可能是等差数列、等比数列或者斐波那契数列。

##### 输入

输入包含多组测试数据。

每组输入 `5` 个整数。

当 `5` 个整数都为 `0` 时，输入结束。

##### 输出

对于每组输入，输出这串数列后面的 `5` 个数字，每个数字之间用一个空格隔开。

##### 样例输入

```text
1 2 3 4 5
1 2 4 8 16
1 2 3 5 8
0 0 0 0 0
```

##### 样例输出

```text
6 7 8 9 10
32 64 128 256 512
13 21 34 55 89
```

##### 解题思路

根据前五项判断序列类型：

1. 如果相邻两项差值都相同，就是等差数列
2. 如果满足连续三项的比例关系，就是等比数列
3. 如果每一项等于前两项之和，就是斐波那契数列

判断出类型后，再按对应规律继续生成后面 `5` 项。

##### 最终代码

```cpp
#include <iostream>
using namespace std;
int main(){
  int a[10];
  while(cin >> a[0] >> a[1] >> a[2] >> a[3] >> a[4]){
    if(a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0){
      break;
    }
  if(a[4] - a[3] == a[3] - a[2] && a[3] - a[2] == a[2] - a[1] && a[2] - a[1] == a[1] - a[0]){
    int d = a[1] - a[0];
    for(int i = 1; i <= 5; i++){
      if(i != 1){
        cout << " ";
      }
      cout << a[4] + i * d;
    }
    cout << endl;
  }else if(a[0] * a[2] == a[1] * a[1] && a[1] * a[3] == a[2] * a[2] && a[2] * a[4] == a[3] * a[3]){
    int q = a[4] / a[3];
    int x = a[4];
    for(int i = 1; i <= 5; i++){
      x *= q;
      if(i != 1){
        cout << " ";
      }
      cout << x;
    }
    cout << endl;
  }else if(a[2] == a[0] + a[1] && a[3] == a[1] + a[2] && a[4] == a[2] + a[3]){
    int x = a[3], y = a[4];
    for(int i = 1; i <= 5; i++){
      int z = x + y;
      if(i != 1){
        cout << " ";
      }
      cout << z;
      x = y;
      y = z;
    }
    cout << endl;
  }
  }
  return 0;
}
```

---

#### D. 复原二叉树

##### 题目描述

给出一棵二叉树的前序遍历和中序遍历结果，要求输出这棵二叉树的后序遍历结果。

##### 输入

输入包含多组测试数据。

每组输入包含两个字符串，分别表示二叉树的前序遍历和中序遍历结果。

每个字符串由不重复的大写字母组成。

##### 输出

对于每组输入，输出对应二叉树的后序遍历结果。

##### 样例输入

```text
DBACEGF ABCDEFG
BCAD CBAD
```

##### 样例输出

```text
ACBFGED
CDAB
```

##### 解题思路

前序遍历的第一个字符一定是当前子树的根。

在中序遍历中找到根的位置后，左边就是左子树，右边就是右子树。

根据左子树节点数量，可以继续把前序遍历切成左子树前序和右子树前序。

递归处理左右子树后，最后输出根节点，就是后序遍历。

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
void postOrder(string pre,string in){
  if(pre.empty()){
    return;
  }
  char root = pre[0];
  int pos = in.find(root);
  string leftIn = in.substr(0,pos);
  string rightIn = in.substr(pos + 1);
  int leftSize = leftIn.size();
  string leftPre = pre.substr(1,leftSize);
  string rightPre = pre.substr(1 + leftSize);
  postOrder(leftPre,leftIn);
  postOrder(rightPre,rightIn);
  cout << root;
}
int main(){
  string pre,in;
  while(cin >> pre >> in){
    postOrder(pre,in);
    cout << endl;
  }
  return 0;
}
```

---

#### E. 子树的后序遍历

##### 题目描述

给出一棵二叉树的中序遍历序列和后序遍历序列，要求输出该二叉树左子树或右子树的后序遍历序列。

##### 输入

输入占三行。

第一行是二叉树的中序遍历序列。

第二行是二叉树的后序遍历序列。

第三行是单个字母，`L` 表示要求输出左子树的后序遍历序列，`R` 表示要求输出右子树的后序遍历序列。

##### 输出

按要求输出该二叉树左子树或右子树的后序遍历序列。

##### 样例输入

```text
BDCEAFHG
DECBHGFA
R
```

##### 样例输出

```text
HGF
```

##### 解题思路

后序遍历的最后一个字符是整棵树的根。

在中序遍历中找到根的位置：

1. 根左边的部分是左子树中序遍历
2. 根右边的部分是右子树中序遍历

左子树有多少个节点，它在后序遍历中就占前多少个字符。

右子树的后序遍历紧跟在左子树后面。

因此可以直接根据左右子树大小切出对应的后序序列。

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
int main(){
  string inorder,postorder;
  char op;
  cin >> inorder;
  cin >> postorder;
  cin >> op;
  int n = postorder.size();
  char root = postorder[n-1];
  int rootpos = inorder.find(root);
  string leftIn = inorder.substr(0,rootpos);
  string rightIn = inorder.substr(rootpos + 1);
  int cntleft = leftIn.size();
  int cntright = rightIn.size();
  string leftpost = postorder.substr(0,cntleft);
  string rightpost = postorder.substr(cntleft,cntright);
  if(op == 'R'){
    cout << rightpost << endl;
  }else if(op == 'L'){
    cout << leftpost << endl;
  }
  return 0;
}
```

---

#### F. 迷宫问题

##### 题目描述

给出一个迷宫，要求求出从起点 `S` 到终点 `E` 的最短路程。

小明只能向上、下、左、右四个方向移动。

##### 输入

第一行输入整数 `T`，表示有 `T` 组测试数据。

每组数据第一行输入两个整数 `N` 和 `M`。

接下来 `N` 行，每行输入 `M` 个字符，表示迷宫。

字符含义如下：

- `S` 表示起点
- `E` 表示终点
- `-` 表示可以通过的空地
- `#` 表示无法通过的障碍

##### 输出

对于每组输入，输出从起点到终点的最短路程。

如果不存在路径，输出 `-1`。

##### 样例输入

```text
1
5 5
S-###
-----
##---
E#---
---##
```

##### 样例输出

```text
9
```

##### 解题思路

迷宫最短路可以使用 BFS。

BFS 从起点开始，一层一层向外扩展，第一次到达终点时的步数就是最短路程。

用队列保存当前位置和当前步数，并用 `visited` 数组避免重复访问。

每次从队列中取出一个位置，尝试向上下左右四个方向移动。

如果新位置没有越界、不是障碍、没有访问过，就加入队列。

##### 最终代码

```cpp
#include <iostream>
#include <queue>
#include <string>
using namespace std;
struct Node{
    int x;
    int y;
    int step;
};
int main(){
    int T;
    cin >> T;
    string maze[105];
    int sx,sy;
    while(T--){
        int N,M;
        cin >> N >> M;
        for(int i = 0; i < N; i++){
            cin >> maze[i];
            for(int j = 0; j < M; j++){
                if(maze[i][j] == 'S'){
                    sx = i;
                    sy = j;
                }
            }
        }
        bool visited[105][105] = {false};
        queue<Node> q;
        q.push({sx,sy,0});
        visited[sx][sy] = true;
        int dx[4] = {-1,1,0,0};
        int dy[4] = {0,0,-1,1};
        int ans = -1;
        while(!q.empty()){
            Node cur = q.front();
            q.pop();
            if(maze[cur.x][cur.y] == 'E'){
                ans = cur.step;
                break;
            }
            for(int i = 0; i < 4; i++){
                int nx = cur.x + dx[i];
                int ny = cur.y + dy[i];
                if(nx < 0 || nx >= N || ny < 0 || ny >= M){
                    continue;
                }
                if(maze[nx][ny] == '#'){
                    continue;
                }
                if(visited[nx][ny]){
                    continue;
                }
                visited[nx][ny] = true;
                q.push({nx,ny,cur.step + 1});
            }
        }
        cout << ans << endl;
    }
    return 0;
}
```

---

### 作业三

#### A. 无向图的深度优先搜索

##### 题目描述

已知一个无向图 `G` 的顶点和边，顶点从 `0` 开始依次编号。

现在需要从 `0` 号顶点开始进行深度优先搜索，访问任一邻接顶点时，编号小的顶点优先。

##### 输入

第一行输入整数 `m` 和 `n`，分别表示顶点数和边数。

接下来 `n` 行，每行输入两个整数，表示一条无向边的两个顶点。

##### 输出

输出该图从 `0` 号顶点开始的深度优先搜索序列。

##### 样例输入

```text
5 5
0 1
2 0
1 3
1 4
4 2
```

##### 样例输出

```text
0 1 3 4 2
```

##### 解题思路

因为访问邻接点时要求编号小的顶点优先，可以使用邻接矩阵存图。

DFS 时从 `0` 到 `m - 1` 依次枚举顶点，如果当前顶点和 `u` 相邻且没有访问过，就递归访问它。

这样天然保证了小编号优先。

##### 最终代码

```cpp
#include <iostream>
using namespace std;
int m,n;
int g[105][105];
bool visited[105];
bool first = true;
void dfs(int u){
  visited[u] = true;
  if(first){
    cout << u;
    first = false;
  }else{
    cout << " " << u;
  }
  for(int v = 0; v < m; v++){
    if(g[u][v] == 1 && !visited[v]){
      dfs(v);
    }
  }
}
int main(){
  cin >> m >> n;
  for(int i = 0; i < n; i++){
    int a,b;
    cin >> a >> b;
    g[a][b] = 1;
    g[b][a] = 1;
  }
  dfs(0);
  cout << endl;
  return 0;
}
```

---

#### B. 最小堆的形成

##### 题目描述

给出 `n` 个节点的完全二叉树数组存储序列。

要求将它调整为最小堆，并输出对应的最小堆存储序列。

##### 输入

第一行输入整数 `n`。

第二行输入 `n` 个节点的完全二叉树数组存储序列。

##### 输出

输出调整后的最小堆存储序列。

##### 样例输入

```text
8
53 17 78 23 45 65 87 9
```

##### 样例输出

```text
9 17 65 23 45 78 87 53
```

##### 解题思路

使用完全二叉树的数组下标关系：

```text
left = 2 * i
right = 2 * i + 1
```

从最后一个非叶子节点 `n / 2` 开始，向前依次执行下沉操作。

每次让当前节点和左右孩子中最小的节点比较，如果孩子更小，就交换并继续向下调整。

##### 最终代码

```cpp
#include <iostream>
#include <vector>
using namespace std;
int n;
vector<int> heap;
void down(int i){
  while(true){
    int smallest = i;
    int left = 2 * i;
    int right = 2 * i + 1;
    if(left <= n && heap[left] < heap[smallest]){
      smallest = left;
    }
    if(right <= n && heap[right] < heap[smallest]){
      smallest = right;
    }
    if(smallest == i){
      break;
    }
    swap(heap[i],heap[smallest]);
    i = smallest;
  }
}
int main(){
  cin >> n;
  heap.resize(n + 1);
  for(int i = 1; i <= n; i++){
    cin >> heap[i];
  }
  for(int i = n / 2; i >= 1; i--){
    down(i);
  }
  for(int i = 1; i <= n; i++){
    if(i > 1) cout << " ";
    cout << heap[i];
  }
  cout << endl;
  return 0;
}
```

---

#### C. 折半查找的次数

##### 题目描述

给出一个无重复数的有序序列。

如果采用折半查找的方式，对于给定的数，要求输出需要比较几次才能找到。

##### 输入

第一行输入 `N`，表示序列中数的个数。

第二行输入一个有序序列。

第三行输入要查找的数 `x`。

##### 输出

如果找到 `x`，输出折半比较的次数。

否则输出 `NO`。

##### 样例输入

```text
11
5 13 19 21 37 56 64 75 80 88 92
19
```

##### 样例输出

```text
2
```

##### 解题思路

使用标准二分查找。

每取一次中间位置 `mid`，就说明进行了一次比较，因此计数器加一。

如果 `a[mid] == x`，输出比较次数。

如果区间缩小到为空仍未找到，输出 `NO`。

##### 最终代码

```cpp
#include <iostream>
using namespace std;
int main(){
    int N;
    cin >> N;
    int a[1005];
    for(int i = 0; i < N; i++){
        cin >> a[i];
    }
    int x;
    cin >> x;
    int left = 0;
    int right = N - 1;
    int cnt = 0;
    while(left <= right){
        int mid =  (left + right) / 2;
        cnt++;
        if(a[mid] == x){
            cout << cnt << endl;
            return 0;
        }else if(a[mid] > x){
            right = mid - 1;
        }else{
            left = mid +1;
        }
    }
    cout << "NO" << endl;
    return 0;
}
```

---

#### D. N 个数的排序

##### 题目描述

给出 `N` 个自然数，输出排序后的这 `N` 个数。

##### 输入

第一行输入整数 `N`。

第二行输入 `N` 个用空格隔开的自然数。

##### 输出

按从小到大的顺序输出 `N` 个数，每个数之间用一个空格间隔。

##### 样例输入

```text
5
9 6 8 7 5
```

##### 样例输出

```text
5 6 7 8 9
```

##### 解题思路

直接使用 `sort` 对数组升序排序。

输出时注意只在两个数之间输出空格，避免行尾多余空格。

##### 最终代码

```cpp
#include <iostream>
#include <algorithm>
using namespace std;
int main(){
    int n;
    cin >> n;
    int a[105];
    for(int i = 0; i < n; i++){
        cin >> a[i];
    }
    sort(a,a + n);
    for(int i = 0; i < n; i++){
        if(i){
            cout << " ";
        }
        cout << a[i];
    }
    cout << endl;
    return 0;
}
```

---

#### E. 班级同学信息查询

##### 题目描述

班级里有 `N` 个同学。

需要保存每个同学的学号、姓名和座位号。

查询时输入某个同学的学号，输出该同学的姓名和座位号。

##### 输入

第一行输入整数 `N`，表示班里同学的人数。

接下来 `N` 行，每行输入一个同学的学号、姓名和座位号。

最后一行输入要查询的同学学号。

##### 输出

输出查询同学的姓名和座位号。

##### 样例输入

```text
3
1 zhang 11
2 wang 22
3 li 33
2
```

##### 样例输出

```text
wang 22
```

##### 解题思路

用结构体保存每个同学的信息。

读入要查询的学号后，顺序枚举所有学生。

如果当前学生学号等于查询学号，就输出姓名和座位号。

##### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
struct Student{
    int id;
    string name;
    int seat;
};
int main(){
    int N;
    cin >> N;
    Student stu[105];
    for(int i = 0; i < N; i++){
        cin >> stu[i].id >> stu[i].name >> stu[i].seat;
    }
    int x;
    cin >> x;
    for(int i = 0; i < N; i++){
        if(stu[i].id == x){
            cout << stu[i].name << " " << stu[i].seat << endl;
            break;
        }
    }
    return 0;
}
```

