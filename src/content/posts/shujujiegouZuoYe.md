---
title: 数据结构作业
published: 2026-05-22
description: 大一下数据结构作业题目总结
tags: [数据结构, notes]
category: C++
draft: false
---
---

# 作业一

## A. 查成绩

### 题目描述

期末考试结束后，数学老师给出了班里同学们的数学成绩，为了快速查成绩，请编程帮助查成绩。

### 输入

第一行为 `N`，`N < 1000`，表示班级人数。

第一行后有 `N` 行，每行两个部分，一个是学号，一个是成绩。

最后一行是要查找成绩同学的学号。

### 输出

输出要查找同学的成绩。

### 样例输入

```text
2
001 90
002 95
002
```

### 样例输出

```text
95
```

### 解题思路

用两个数组分别保存学号和成绩。读入要查询的学号后，从前往后顺序查找，如果当前学号和目标学号相同，就输出对应的成绩并结束。

### 最终代码

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

## B. 插入数据

### 题目描述

已有一个整数序列，现在要在不同的位置插入一些整数，请输出插入数据后的序列。

### 输入

第一行是 `N`，`N < 1000`，表示原序列中元素的个数。

第二行是 `N` 个整数。

第三行是要插入的元素个数 `M`，`M < 1000`。

第四行开始有 `M` 行，每行是一对数据 `k` 和 `x`，表示要在原序列第 `k` 个位置插入整数 `x`。

### 输出

输出插入元素后的整数序列。

### 样例输入

```text
5
1 2 3 4 5
2
1 11
3 33
```

### 样例输出

```text
11 1 2 33 3 4 5
```

### 解题思路

使用 `vector` 保存原整数序列。每次插入时使用 `insert` 函数。

因为题目给出的 `k` 是相对于原序列的位置，而前面已经插入了 `i` 个元素，所以第 `i` 次插入时，实际插入位置为：

```text
k - 1 + i
```

### 最终代码

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

## C. 二路归并

### 题目描述

有两个按元素值递增有序的整数顺序表 `A` 和 `B`，设计一个算法将顺序表 `A` 和 `B` 的全部元素合并到一个递增有序顺序表 `C` 中，并依次输出 `C` 中的元素。

### 输入

输入占两行，依次是 `A` 和 `B` 的序列，元素个数都小于 `100`。

### 输出

依次输出 `C` 中的元素。

### 样例输入

```text
1 2 3 4 5
1 2 3 4 6
```

### 样例输出

```text
1 1 2 2 3 3 4 4 5 6
```

### 解题思路

两个序列本身已经递增有序，所以可以用双指针

令 `i` 指向 `A` 的当前位置，`j` 指向 `B` 的当前位置。每次比较 `A[i]` 和 `B[j]`，把较小的元素放入 `C`。如果其中一个序列已经全部放入 `C`，就把另一个序列剩下的元素全部加入

本题没有给出每行元素个数，所以使用 `getline` 读入整行，再手动扫描字符串得到整数

### 最终代码

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

## D. 最大值个数

### 题目描述

有一个整数单链表 `L`，其中可能存在多个值相同的结点，设计一个算法查找 `L` 中最大值结点的个数。

### 输入

输入单链表 `L` 中的元素，个数不定。

### 输出

输出最大值结点的个数。

### 样例输入

```text
1 2 3 4 5 5 20 20 1 2 3 4 5
```

### 样例输出

```text
2
```

### 解题思路

题目描述的是单链表，本质操作就是从头到尾遍历一次

读入过程中维护两个变量：

```text
maxn 表示当前最大值
cnt  表示当前最大值出现次数
```

如果读到的新元素比 `maxn` 大，就更新 `maxn`，并把 `cnt` 重置为 `1`。如果读到的新元素等于 `maxn`，就让 `cnt` 加 `1`

### 最终代码

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

## E. 约瑟夫问题

### 题目描述

有 `n` 个小孩围成一圈，给他们从 `1` 开始依次编号。从编号为 `1` 的小孩开始报数，数到第 `m` 个小孩出列，然后从出列的下一个小孩重新开始报数。如此反复直到所有的小孩全部出列为止，求整个出列序列。

### 输入

输入占一行，为 `n` 和 `m`，其中 `n < 100`，`0 < m < n`。

### 输出

输出整个出列序列。

### 样例输入

```text
6 5
```

### 样例输出

```text
5 4 6 2 3 1
```

### 解题思路

用 `vector` 保存当前还在圈中的小孩编号。

设当前报数起点下标为 `k`，当前剩余人数为 `len`，则每次出列的小孩下标为：

```text
k = (k + m - 1) % len
```

删除当前小孩后，`k` 正好指向下一个开始报数的人

### 最终代码

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

## F. 括号配对

### 题目描述

设计一个算法利用顺序栈检查用户输入的表达式中括号是否配对。假设表达式中可能含有圆括号 `()`、中括号 `[]` 和大括号 `{}`。

### 输入

输入占一行，为含有三种括号的表达式，最长 `100` 个符号。

### 输出

匹配时输出 `YES`。

小括号不匹配输出 `NO1`，中括号不匹配输出 `NO2`，大括号不匹配输出 `NO3`。

### 样例输入

```text
{([a])}
```

### 样例输出

```text
YES
```

### 解题思路

使用字符数组模拟顺序栈

遇到左括号时，将它入栈。遇到右括号时，检查栈顶是否是对应的左括号。如果栈为空，或者栈顶括号类型不对应，就说明不匹配，按照当前右括号类型输出对应的 `NO`

扫描结束后，如果栈为空，说明全部括号匹配；如果栈不为空，就根据栈顶剩余的左括号类型输出对应结果

### 最终代码

```cpp
#include <iostream>
#include <string>
using namespace std;
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
            if(top == -1 || st[top] != '('){
                cout << "NO1" << endl;
                return 0;
            }
            top--;
        }
        else if(s[i] == ']'){
            if(top == -1 || st[top] != '['){
                cout << "NO2" << endl;
                return 0;
            }
            top--;
        }
        else if(s[i] == '}'){
            if(top == -1 || st[top] != '{'){
                cout << "NO3" << endl;
                return 0;
            }
            top--;
        }
    }
    if(top == -1)
        cout << "YES" << endl;
    else if(st[top] == '(')
        cout << "NO1" << endl;
    else if(st[top] == '[')
        cout << "NO2" << endl;
    else
        cout << "NO3" << endl;
    return 0;
}
```

---

## G. 后缀表达式

### 题目描述

给出一个中缀表达式，输出该表达式的后缀表达式。

### 输入

输入占一行，为一个中缀表达式。运算符只有 `+`、`-`、`*`、`/`，最多 `1000` 个字符。

### 输出

输出后缀表达式。

### 样例输入

```text
(56-20)/(4+2)
```

### 样例输出

```text
56 20 - 4 2 + /
```

### 解题思路

中缀表达式转后缀表达式可以使用运算符栈

处理规则如下：

1. 如果遇到操作数，直接加入答案
2. 如果遇到左括号，直接入栈
3. 如果遇到右括号，就一直弹出栈顶运算符，直到遇到左括号
4. 如果遇到普通运算符，就弹出栈顶优先级大于等于当前运算符的运算符，然后再把当前运算符入栈
5. 扫描结束后，将栈中剩余运算符依次弹出

样例中有多位数，所以扫描操作数时，需要把连续的数字或字母作为一个整体

### 最终代码

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

## H. 字符串反转

### 题目描述

小 C 很喜欢倒着写单词。现在给你一行小 C 写的文本，你需要把每个单词都反转并输出。

### 输入

输入包含多组测试样例。

第一行为一个整数 `T`，代表测试样例的数量，后面跟着 `T` 个测试样例。

每个测试样例占一行，包含多个单词，一行最多有 `1000` 个字符。

### 输出

对于每一个测试样例，输出转换后的文本。

### 样例输入

```text
3
olleh !dlrow
I ekil .bulcmca
I evol .mca
```

### 样例输出

```text
hello world!
I like acmclub.
I love acm.
```

### 解题思路

逐行读取字符串，使用 `word` 临时保存当前单词

如果当前字符不是空格，就加入 `word`。如果遇到空格，就把 `word` 倒序输出，然后输出空格，并清空 `word`

一行结束后，还需要把最后一个单词倒序输出

标点符号也属于单词的一部分，所以会随着单词一起反转

### 最终代码

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