---
title: 高级语言程序设计C++基础
published: 2025-09-29
description: 大一C++学习记录
tags: [C++]
category: C++
draft: false
---
作为大一开始学c++的记录，纯基础
## 一些会用到的代码
记录一下一些基础的代码
### 小写字母转大写
```c++
#include <bits/stdc++.h>
using namespace std;
signed main()
{
    char n;
    cin >> n;
    char m = n - 32;
    cout << m;
    return 0;
}
```
利用大小写字母ASCII码差32实现
### 数字反转
```c++
#include <bits/stdc++.h>
using namespace std;
signed main()
{
    string a;
    cin >> a;
    int len = a.size();
    for(int i = len - 1; i >= 0; i--)
    cout << a[i];
    return 0;
}
```
字符串练习
### 素数判断
```c++
#include <bits/stdc++.h>
using namespace std;
bool isPrime(int n)
{
    if(n < 2) return false;
    for(int i = 2; i * i <= n; i++){
        if(n % i == 0) return 0;
    }
    return true;
}
signed main()
{
    int a;
    cin >> a;
    if(isPrime(a)){
        cout << "是素数";
    } 
    else{
        cout << "不是素数";
    }
    return 0;
}
```
写个isPrime判断素数，小于2直接返回false，大于2进行开平方判断
### ceil向上取整
题目来自洛谷 <https://www.luogu.com.cn/problem/P5707>
```c++
#include <bits/stdc++.h>
using namespace std;
signed main()
{
    double s,v,a,b;
    cin >> s >> v;
    int t = ceil(s / v) + 10;
    int n = 8 * 60 + 24 * 60;
    n -= t;
    if(n >= 1440){
        n -= 1440;
    }
    a = n / 60;
    b = n % 60;
    if( a < 10){
        if(b < 10){
            cout << 0 << a << ":0" << b;
        }else {
            cout << 0 << a << ":" << b;
        }
    }else {
        if(b < 10){
            cout << a << ":0" << b;
        }else {
            cout << a << ":" << b;
        }
    }
    return 0;
}
```
如果用到C的格式化输出就不会看着这么难受...
```c++
#include <bits/stdc++.h>
using namespace std;
signed main() {
    int s, v;
    scanf("%d %d", &s, &v);
    int t = (s + v - 1) / v + 10; //直接用-1替代了ceil，不取浮点数
    int n = 480 - t;    //八点的分钟
    if (n < 0) n += 1440;  //超过一天回退到前一天
    printf("%02d:%02d", n / 60, n % 60);
    return 0;
}
```
确实看着精简多了

其实感觉这里对ceil向上取整更好的例子是这个<https://www.luogu.com.cn/problem/B2029>
```c++
#include <bits/stdc++.h>
using namespace std;
signed main()
{
    int h,r;
    cin >> h >> r;
    double v = 3.14 * r * r * h ;
    int n = ceil(20000 / v);
    cout << n ;
    return 0;
}
```
v体积一定要是double 用int就把小数截断了
## iomanip头文件控制输出精度
例<https://www.luogu.com.cn/problem/P5706>

主要是用来控制输出小数点后几位数字
```c++
#include <bits/stdc++.h>
using namespace std;
signed main()
{
    double t;
    int n;
    cin >> t >> n;
    double drink = t / n;
    int cup = 2 * n;
    cout << fixed << setprecision(3) << drink << endl;
    cout << cup;
    return 0;
}
```
使用
```c++
std::cout << std::fixed << std::setprecision()
```
来控制小数点后面输出，设置宽度setw暂不展示