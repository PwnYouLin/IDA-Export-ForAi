[English](README_EN.md) | 简体中文

# IDA Export for AI

**无需打开 IDA，一条命令导出二进制文件的完整分析数据。**

**AI 逆向，零配置，直接喂给 Cursor / Claude Code / Copilot。**

Simple · Fast · Intelligent · Low Cost

## 核心理念

Text、Source Code、Shell 是 LLM 原生语言。

AI 飞速发展，没有固定模式，工具应该保持简单。

把 IDA 反编译结果导出为源码文件，直接丢进任意 AI IDE，天然适配索引、并行、切片等优化。

## 快速开始

### 环境要求

- **IDA Pro 9.0+**，已安装 `idalib`（IDA 9.0+ 自带）
- **idapro Python 包**：`pip install idapro`
- **Hex-Rays 反编译器**（可选，没有则只导出反汇编）

### 基本用法

```bash
# 最简用法 - 自动检测 IDA 安装目录
python standalone_export.py /path/to/binary

# 指定输出目录
python standalone_export.py /path/to/binary -o /path/to/output

# 指定 IDA 安装目录（自动检测失败时）
python standalone_export.py /path/to/binary --idadir ~/ida-pro-9.3

# 跳过自动分析（已有 .i64/.idb 数据库时加速）
python standalone_export.py /path/to/binary --skip-analysis
```

### IDA 目录检测

脚本按以下顺序查找 IDA 安装目录：

1. `--idadir` 命令行参数
2. `IDADIR` 环境变量
3. 自动搜索常见路径：`~/ida-pro-9.*`、`~/ida`、`/opt/ida-pro-9.*`、`/opt/ida`

首次运行时，脚本会自动将检测到的路径写入 `~/.idapro/ida-config.json`。

### 完整示例

```bash
# 安装依赖
pip install idapro

# 导出 MIPS 固件
python standalone_export.py ./firmware/cstecgi.cgi

# 导出后目录结构
# ./export-for-ai/
# ├── decompile/          # 反编译的 C 代码
# │   ├── 401f9c.c
# │   └── 4025c8.c
# ├── disassembly/        # 反编译失败时的反汇编回退
# ├── strings.txt         # 字符串表
# ├── imports.txt         # 导入表
# ├── exports.txt         # 导出表
# ├── pointers.txt        # 指针引用
# ├── memory/             # 内存 hexdump
# └── function_index.txt  # 函数索引
```

## 导出内容

| 文件/目录               | 内容           | 说明                                                                        |
| ----------------------- | -------------- | --------------------------------------------------------------------------- |
| `decompile/`            | 反编译 C 代码  | 每个成功反编译的函数一个 `.c` 文件，包含函数名、地址、调用者、被调用者      |
| `disassembly/`          | 反汇编回退代码 | 反编译失败时回退到反汇编导出，每个函数一个 `.asm` 文件，保留相同元数据       |
| `function_index.txt`    | 函数索引       | 所有导出函数的完整索引，包含调用关系和文件路径                               |
| `strings.txt`           | 字符串表       | 包含地址、长度、类型(ASCII/UTF-16/UTF-32)、内容                             |
| `imports.txt`           | 导入表         | 格式：`地址:函数名`                                                         |
| `exports.txt`           | 导出表         | 格式：`地址:函数名`                                                         |
| `pointers.txt`          | 指针引用       | 数据指针分类（函数指针、字符串指针、导入指针等）                             |
| `memory/`               | 内存 hexdump   | 按 1MB 分片，hexdump 格式，包含地址、十六进制、ASCII                        |
| `disassembly_fallback.txt` | 回退列表   | 记录使用反汇编回退的函数及失败原因                                           |
| `decompile_failed.txt`  | 失败列表       | 记录反编译和反汇编都失败的函数                                               |
| `decompile_skipped.txt` | 跳过列表       | 记录被跳过的库函数和无效函数                                                 |

## 功能特性

### 反编译函数导出

每个函数优先导出为独立的 `.c` 文件；如果反编译失败，则回退导出到 `disassembly/` 目录中的 `.asm` 文件。两种输出都保留元数据头：

```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * export-type: decompile
 * callers: 0x402000, 0x403000
 * callees: 0x404000, 0x405000
 */

// 反编译代码...
```

### 调用关系分析

- **Callers**：哪些函数调用了当前函数
- **Callees**：当前函数调用了哪些函数
- 帮助 AI 理解函数间的依赖关系和调用链

### 指针分析

自动扫描数据段中的指针引用并分类：
- 函数指针（function_pointer）
- 字符串指针（string_pointer）
- 导入表指针（import_pointer）
- 数据指针（data_pointer）

### 断点续传

导出过程支持断点续传。如果中途中断，重新运行相同的命令即可从上次进度继续。

### 内存导出

- 按段（segment）导出所有内存数据
- 每个文件最大 1MB，自动分片
- Hexdump 格式，包含地址、十六进制字节、ASCII 显示

## 与 AI IDE 配合使用

将导出目录直接拖入 AI IDE 工作区即可：

```bash
# 导出后，用 Cursor / Claude Code / Copilot 打开
cursor ./export-for-ai/
```

也可以在 IDB 目录下添加更多上下文：

| 目录     | 内容                                 |
| -------- | ------------------------------------ |
| `apk/`   | APK 反编译目录（APKLab 一键导出）    |
| `docs/`  | 逆向分析报告、笔记                   |
| `codes/` | exp、Frida scripts、decryptor 等脚本 |

## 命令行参数

```
usage: standalone_export.py [-h] [-o OUTPUT] [--skip-analysis] [--idadir IDADIR] binary

positional arguments:
  binary                要分析的二进制文件路径

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        输出目录 (默认: <binary所在目录>/export-for-ai)
  --skip-analysis       跳过自动分析 (如果已有 .i64/.idb 数据库可使用此选项加速)
  --idadir IDADIR       指定 IDA 安装目录 (默认自动检测)
```

## 与旧版 INP.py 插件的区别

| | INP.py (旧版插件) | standalone_export.py (新版) |
|---|---|---|
| 运行方式 | 需要打开 IDA GUI | 命令行直接运行 |
| 依赖 | IDA Pro GUI | idalib (headless) |
| 批量处理 | 需要手动逐个打开 | 脚本批量处理多个文件 |
| 自动化 | 有限 | 完全自动化，适合 CI/CD |
