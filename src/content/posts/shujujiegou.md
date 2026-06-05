---
title: 数据结构合集
published: 2026-05-29
description: 大一下数据结构作业+实践+笔记全收集
tags: [数据结构, notes]
category: C++
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