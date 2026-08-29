# 更新日志

## v0.1.1 (2026-08-29)

- 安装方式统一为四方式（对齐发布规范 §3.3.1）：方式一 `npx -y @yottameta/yotta-triage --agent <name>` / `--dir <dir>`（推荐，走 npm 源）；方式二 `git clone https://github.com/YottaMeta/yotta-triage.git`；方式三 GitHub Download ZIP；方式四 `bash install.sh --agent/--dir/--list`。移除 `npx skills` 与 `-g` 推荐；中英双 README 安装节同步。
- 版本对齐：package.json / SKILL.md / CHANGELOG / 引擎 VERSION / 测试断言 / README 锚点 = 0.1.1。
- 无功能变更（仅文档与版本同步）。

## v0.1.0 (2026-08-28)

初始发布：

- 引擎：零依赖（Python 3.8+ 标准库）恶意样本静态初筛。
- 哈希：MD5 / SHA1 / SHA256（流式计算，大文件不吃内存）。
- 类型识别：魔数识别 PE / ELF / Mach-O / PDF / ZIP / gzip / 7z / RAR / OLE / 图片 / pyc / Java class，
  另含 UTF-8 文本 / shebang 脚本识别。
- 熵：整体 Shannon 熵 + PE 区段熵（加壳 / 加密 / 压缩线索）。
- 字符串：可打印字符串（ASCII + UTF-16LE），分类提取 URL / 域名 / IP / 邮箱 / 可疑命令 / 路径 / 长 base64。
- PE 头解析：机器类型 / 时间戳 / 可选头 / 区段表（名称 / 特性 / 熵），识别加壳区段（UPX 等）与 RWX 区段。
- ELF 头解析：位宽 / 字节序 / 机器 / 类型 / 入口 / 程序头与节头，识别 RWE 段与 RWX 节。
- 风险分级：静态指标加权给出 info/low/medium/high/critical 线索级提示（评分 + 理由）。
- IOC 输出：hash / URL / 域 / IP / 邮箱汇总，JSON 供元情（yotta-intel）消费。
- 输出：text / JSON / Markdown；--ioc-only 只输出 IOC。
- 测试：65 个用例全绿；含 CLI 端到端（文件 / 目录 / 退出码 / JSON / IOC / 输出文件）。
- 文档：SKILL.md + README 中英双版 + references（triage-spec / risk-model）。
