---
title: 用 CC-Switch 简单配置 Codex、Claude Code 等 Agent 工具
published: 2026-04-26
description: 面向刚接触 AI Coding Agent 的人，简单介绍 Codex、Claude Code 与网页 AI 的区别，并用 CC-Switch 管理和切换不同 API 配置
tags: [AI, Agent, Codex]
category: AI
draft: false
---

> 这篇文章主要写给刚开始接触 AI Coding Agent，但觉得配置麻烦、不知道从哪里下手的人

## 关于 CCswitch

CC-Switch像是一个配置管理器。Codex、Claude Code、Gemini CLI、OpenCode 这类工具本身负责和模型交互、读取项目、修改文件、运行命令 CC-Switch 负责帮你管理不同的 API Provider，比如官方 API、中转站、聚合平台或者你自己的反代

如果完全手动配置，你需要自己去改 Codex、Claude Code 等工具的配置文件,非常非常之麻烦，每一次改API都需要手动切，用 CC-Switch 之后，很多事情就能直接完成，添加 Provider、填写 API Key、设置接口地址、选择模型，然后一键切换

## 网页 AI 与 Coding Agent 区别

Codex 或 Claude Code和平时在 ChatGPT、DeepSeek 豆包什么的这类网页里让 AI 写代码，不也一样是在让 AI 干活吗？

表面上看确实很像，但实际工作流差很多...

网页 AI 是你把需求发给它，它生成一段代码，你ctrl+ c + ctrl + v到本地运行，遇到报错，再把报错复制回去，让它继续分析。整个循环里，真正负责运行代码、收集报错、决定下一步的人，还是你自己

Coding Agent 则更进一步。它不只是回答问题，而是可以进入你的项目目录，读取文件、理解上下文、修改代码、执行命令、查看测试结果，并根据新的输出继续下一轮操作。也就是说，它把原来由人完成的“复制、运行、粘贴报错、继续追问”这一层循环接了过去

这就是常说的 Agent Loop：模型负责推理，工具负责行动，循环负责把行动结果继续喂回模型。网页聊天里，这个循环主要靠人手动维持；Codex、Claude Code 这类工具则把循环内置到了工具本身

所以它们更适合日常开发场景，就比如：

- 阅读一个github开源项目；
- 根据需求补功能；
- 修 Bug
- 跑测试并根据失败结果继续修改；
- 生成文档、pr描述或代码审查意见等

这也是我建议计算机专业大学生早点尝试这类工具的原因，为了尽早感受一种新的开发协作方式，这也是时代的必然发展方向，你负责判断方向、约束需求和验收结果，Agent 负责在项目里持续推进细节....

## CC-Switch 的作用

既然 Codex 和 Claude Code 自己就是 Agent，为什么还需要 CC-Switch？？？

因为配置很容易变乱啊

不同工具的配置文件位置、格式、字段名都不一样。比如 Codex 通常会涉及 API Key、模型名、接口地址、Provider 类型等配置；Claude Code 又有另一套环境变量和配置格式。如果你同时想用官方 API、中转站、不同模型、不同账号，手动改配置就会很烦....

CC-Switch 解决的就是这个问题：它把不同 Provider 的配置集中保存起来，然后在你切换时，把对应配置写入 Codex、Claude Code 等工具需要的配置文件里

## 准备使用codex

开始之前，你至少需要准备这几样东西：

1. 一个已经安装好的 Agent 工具，比如 Codex 或 Claude Code；
2. 一个可用的 API Key，或者一个已经能登录使用的官方账号；
3. 如果使用中转站，还需要拿到它提供的接口地址、模型名和密钥，中转站很多，比如linuxdo上一抓一大把，或者搜一搜，建议不要找小众免费公益站，容易跑路投毒！！！；
4. 安装 CC-Switch

Codex 可以参考官方方式安装：（下得慢记得加个npm镜像）

```bash
npm install -g @openai/codex
```
觉得慢加npm镜像
```bash
npm install -g @openai/codex --registry=https://registry.npmmirror.com
```

安装完成后，在项目目录里执行：

```bash
codex
```

如果你使用的是官方登录流程，就按终端里的提示登录即可，如果你使用 API Key 或中转站，那后面的配置就可以交给 CC-Switch 来管理

CC-Switch 可以从项目的 [Releases](https://github.com/farion1231/cc-switch/releases) 下载

## 用 CC-Switch 添加 Provider

打开 CC-Switch 后，最简单的是找个中转站一键导入，看看是怎么配置的，然后学习


如果没有一键导入，就手动添加，跟着CCSwitch引导走

## 切换到 Codex 并测试

切换配置后最好关闭当前终端，重新打开一个终端再运行：

```bash
codex
```

然后问一个简单问题测试一下：

```text
你是什么模型
```

如果 Codex 能正常回复，那说明基本配置已经成功。

如果报错，可以优先检查这几项：

- API Key 是否复制完整；
- Base URL 是否路径正确，比如有的平台需要 `/v1`，但是有的不需要你补v1，导致后面变成了/v1/v1，也会导致报错；
- 模型名是否和平台后台显示的一致；
- 当前 Provider 是否真的已经启用；
- Codex 是否已经重启

## 中转站存在一些风险

GPT、Claude 等高级模型的使用成本相对较高，所以很多人会通过拼车、中转站降低使用成本。现在常见的一些中转站框架，比如 NewAPI、Sub2API，也经常会提供方便导入到 CC-Switch 的配置

但是中转站是存在投毒的风险的，可能会盗取你电脑的重要信息等等，这也就是为什么不能找那种过于小众的，还有那种公益站，免费的也是最贵的，信息泄露就不好了

具体怎么实现的，我可以给你举个例子，比如你的项目主要是用go或者rust等偏项目的语言，就容易被投毒，一般像病毒一样潜在不会被发现，当你开启所有权限之后才开始显现，比如给你pip一些风险，github投毒等等，所以最好注意一下，这个真的很难避免


## 最后

总结一下，Codex、Claude Code 这类工具是让 AI 真正进入开发流程，能读项目、改文件、跑命令，并根据结果继续迭代，也是未来vibe coding的大趋势....

