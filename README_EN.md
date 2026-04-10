English | [简体中文](README.md)

# IDA Export for AI

**Export complete binary analysis data with a single command, no IDA GUI required.**

**AI Reverse Engineering, Zero Configuration — feed directly to Cursor / Claude Code / Copilot.**

Simple · Fast · Intelligent · Low Cost

## Core Philosophy

Text, Source Code, and Shell are LLM's native languages.

AI is evolving rapidly with no fixed patterns — tools should stay simple.

Export IDA decompilation results as source files, drop them into any AI IDE, and naturally benefit from indexing, parallelism, chunking, and other optimizations.

## Quick Start

### Requirements

- **IDA Pro 9.0+** with `idalib` (included in IDA 9.0+)
- **idapro Python package**: `pip install idapro`
- **Hex-Rays decompiler** (optional; falls back to disassembly if unavailable)

### Basic Usage

```bash
# Minimal — auto-detect IDA installation
python standalone_export.py /path/to/binary

# Specify output directory
python standalone_export.py /path/to/binary -o /path/to/output

# Specify IDA installation directory (if auto-detection fails)
python standalone_export.py /path/to/binary --idadir ~/ida-pro-9.3

# Skip auto-analysis (faster if .i64/.idb database already exists)
python standalone_export.py /path/to/binary --skip-analysis
```

### IDA Directory Detection

The script searches for the IDA installation in this order:

1. `--idadir` command-line argument
2. `IDADIR` environment variable
3. Auto-search common paths: `~/ida-pro-9.*`, `~/ida`, `/opt/ida-pro-9.*`, `/opt/ida`

On first run, the detected path is automatically saved to `~/.idapro/ida-config.json`.

### Full Example

```bash
# Install dependency
pip install idapro

# Export a MIPS firmware binary
python standalone_export.py ./firmware/cstecgi.cgi

# Output directory structure
# ./export-for-ai/
# ├── decompile/          # Decompiled C code
# │   ├── 401f9c.c
# │   └── 4025c8.c
# ├── disassembly/        # Disassembly fallback when decompilation fails
# ├── strings.txt         # String table
# ├── imports.txt         # Import table
# ├── exports.txt         # Export table
# ├── pointers.txt        # Pointer references
# ├── memory/             # Memory hexdump
# └── function_index.txt  # Function index
```

## Exported Content

| File/Directory          | Content                    | Description                                                                                 |
| ----------------------- | -------------------------- | ------------------------------------------------------------------------------------------- |
| `decompile/`            | Decompiled C code          | Each successfully decompiled function as a `.c` file, with name, address, callers, callees  |
| `disassembly/`          | Disassembly fallback code  | Falls back to disassembly when decompilation fails, one `.asm` file per function            |
| `function_index.txt`    | Function index             | Complete index of all exported functions with call relationships and file paths             |
| `strings.txt`           | String table               | Includes address, length, type (ASCII/UTF-16/UTF-32), content                               |
| `imports.txt`           | Import table               | Format: `address:function_name`                                                             |
| `exports.txt`           | Export table               | Format: `address:function_name`                                                             |
| `pointers.txt`          | Pointer references         | Classified pointers (function, string, import, data pointers)                               |
| `memory/`               | Memory hexdump             | 1MB chunks, hexdump format with address, hex bytes, ASCII                                   |
| `disassembly_fallback.txt` | Fallback list           | Records functions that fell back to disassembly and the reasons                              |
| `decompile_failed.txt`  | Hard failure list          | Records functions where both decompilation and disassembly failed                           |
| `decompile_skipped.txt` | Skipped functions list     | Records skipped library functions and invalid functions                                      |

## Features

### Decompiled Function Export

Each function is exported as a separate `.c` file when decompilation succeeds. If decompilation fails, the function is exported to `disassembly/` as a `.asm` file instead. Both outputs keep the same metadata header:

```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * export-type: decompile
 * callers: 0x402000, 0x403000
 * callees: 0x404000, 0x405000
 */

// Decompiled code...
```

### Call Relationship Analysis

- **Callers**: Which functions call the current function
- **Callees**: Which functions are called by the current function
- Helps AI understand function dependencies and call chains

### Pointer Analysis

Automatically scans data segments for pointer references and classifies them:
- Function pointers (function_pointer)
- String pointers (string_pointer)
- Import table pointers (import_pointer)
- Data pointers (data_pointer)

### Resume Support

Export supports resuming from where it left off. If interrupted, simply re-run the same command to continue.

### Memory Export

- Exports all memory data by segments
- Maximum 1MB per file, automatically chunked
- Hexdump format with address, hex bytes, and ASCII display

## Working with AI IDEs

Drop the export directory directly into your AI IDE workspace:

```bash
# After export, open with Cursor / Claude Code / Copilot
cursor ./export-for-ai/
```

You can also add more context alongside the export:

| Directory | Content                                              |
| --------- | ---------------------------------------------------- |
| `apk/`    | APK decompilation directory (APKLab one-click export) |
| `docs/`   | Reverse engineering reports, notes                   |
| `codes/`  | exp, Frida scripts, decryptor, etc.                  |

## Command-Line Arguments

```
usage: standalone_export.py [-h] [-o OUTPUT] [--skip-analysis] [--idadir IDADIR] binary

positional arguments:
  binary                Path to the binary file to analyze

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output directory (default: <binary_dir>/export-for-ai)
  --skip-analysis       Skip auto-analysis (use if .i64/.idb database already exists)
  --idadir IDADIR       IDA installation directory (auto-detected by default)
```

## Comparison with Legacy INP.py Plugin

| | INP.py (Legacy Plugin) | standalone_export.py (Current) |
|---|---|---|
| How to run | Requires IDA GUI | Command line, no GUI needed |
| Dependency | IDA Pro GUI | idalib (headless) |
| Batch processing | Must open files one by one | Scriptable, batch-friendly |
| Automation | Limited | Fully automated, CI/CD ready |
