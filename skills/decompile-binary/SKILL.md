---
name: decompile-binary
description: 'Use when encountering binary files (ELF, PE, Mach-O, firmware, .so, .dll, .exe, CGI, bin) that need reverse engineering analysis. Decompiles binaries using IDA Pro idalib, exports C source code, strings, imports, exports, pointers, memory dumps. Keywords: binary analysis, decompile, disassemble, reverse engineering, firmware, ELF, MIPS, ARM, x86, vulnerability, 逆向, 反编译, 二进制分析'
argument-hint: '/path/to/binary'
---

# Decompile Binary with IDA Pro

Export full analysis data from binary files using IDA Pro's headless idalib — decompiled C code, disassembly, strings, imports/exports, pointers, and memory dumps.

## When to Use

- User provides a binary file (ELF, PE, Mach-O, firmware blob, shared library, etc.) and wants to analyze it
- Need to understand what a binary does (vulnerability research, malware analysis, CTF challenges)
- User asks to "decompile", "disassemble", "reverse engineer", or "analyze" a binary
- Working with IoT firmware, CGI binaries, embedded binaries
- Need C pseudocode from stripped binaries for AI-assisted analysis

## Prerequisites

- IDA Pro 9.0+ installed (with idalib)
- `idapro` Python package: `pip install idapro`
- Hex-Rays decompiler license (optional; falls back to disassembly)

## Procedure

### Step 1: Locate the Binary

Confirm the binary file path. If the user provides a directory, look for common binary files:

```bash
# Check file type
file /path/to/binary
```

### Step 2: Run the Export Script

The export script is located at `IDA-NO-MCP/standalone_export.py` (adjust path relative to workspace root).

```bash
# Default: outputs to <binary_dir>/export-for-ai/
python3 IDA-NO-MCP/standalone_export.py /path/to/binary

# Specify output directory (recommended for AI IDE indexing)
python3 IDA-NO-MCP/standalone_export.py /path/to/binary -o /path/to/output

# Skip auto-analysis if .i64/.idb database already exists (faster)
python3 IDA-NO-MCP/standalone_export.py /path/to/binary --skip-analysis

# Manually specify IDA installation directory
python3 IDA-NO-MCP/standalone_export.py /path/to/binary --idadir ~/ida-pro-9.3
```

**Output directory rules**:
- Default: `<binary_file_dir>/export-for-ai/`
- Example: binary at `/home/user/firmware/cstecgi.cgi` → output to `/home/user/firmware/export-for-ai/`
- Use `-o` to specify any custom output path
- If the output directory already contains previous export data, the script automatically skips already-processed functions (resume support)

The script auto-detects IDA in `~/ida-pro-9.*`, `~/ida`, `/opt/ida-pro-9.*`, `/opt/ida`.

### Step 3: Wait for Export to Complete

The script will:
1. Open the binary with IDA idalib (headless, no GUI)
2. Run auto-analysis
3. Export all data to the output directory

This may take a few minutes for large binaries. Large binaries (thousands of functions) may take longer.

### Step 4: Review the Output

**Output directory structure and file naming**:

```
export-for-ai/
├── decompile/                    # Successfully decompiled functions, one .c per function
│   ├── 401f9c.c                  # Filename = function address in uppercase hex
│   ├── 4025c8.c                  # Example: address 0x4025c8 → 4025c8.c
│   └── 402a9c.c
├── disassembly/                  # Functions where decompilation failed, fallback to disasm
│   └── 403000.asm                # Same naming, but .asm extension
├── function_index.txt            # Index of all exported functions with call relationships
├── strings.txt                   # All strings (address | length | type | content)
├── imports.txt                   # Import table (address:function_name)
├── exports.txt                   # Export table (address:function_name)
├── pointers.txt                  # Pointer references (source_addr | segment | target_addr | type)
├── memory/                       # Memory hexdump, 1MB chunks
│   ├── 00400000--00400190.txt    # Filename = start_addr--end_addr
│   └── 004001C0--0040F750.txt
├── disassembly_fallback.txt      # List of functions that fell back to disassembly + reasons
├── decompile_failed.txt          # Functions that failed both decompilation and disassembly
└── decompile_skipped.txt         # Skipped library/invalid functions
```

**Function file naming convention**:
- Decompilation succeeded: `decompile/<UPPER_HEX>.c` (e.g. `4025c8.c` = function `sub_4025c8`)
- Decompilation failed: `disassembly/<UPPER_HEX>.asm` (e.g. `403000.asm`)
- Memory files: `memory/<start_addr>--<end_addr>.txt` (8-digit hex, e.g. `00400000--00400190.txt`)

**How to find a specific function**:
- By function name → search in `function_index.txt` to find the corresponding filename
- By address → read `decompile/<address>.c` directly (uppercase hex, no `0x` prefix)
- By string → search in `strings.txt` for the string, get its address, then find the function

### Step 5: Analyze with AI

Read the relevant decompiled `.c` files to understand the binary:

- Start from `exports.txt` and `function_index.txt` to find entry points
- Read specific `decompile/*.c` files for function-level analysis
- Use `strings.txt` and `imports.txt` for quick triage
- Cross-reference callers/callees in each `.c` file header to trace call chains

Each decompiled file has a metadata header:
```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * export-type: decompile
 * callers: 0x402000, 0x403000
 * callees: 0x404000, 0x405000
 */
```

## Troubleshooting

- **"Cannot load IDA library file libidalib.so"**: Set `--idadir` or `export IDADIR=/path/to/ida`
- **IDA 9.0+ required**: The script uses `idapro` which requires IDA 9.0+
- **Decompilation failures**: Check `disassembly_fallback.txt` and `decompile_failed.txt` — some architectures/functions may only produce disassembly
- **Large binaries**: The script supports resume — re-run if interrupted

## Architecture Support

IDA Pro with Hex-Rays supports decompilation for: x86/x64, ARM/ARM64, MIPS, PowerPC, RISC-V, and more. Without Hex-Rays, the script exports disassembly only.
