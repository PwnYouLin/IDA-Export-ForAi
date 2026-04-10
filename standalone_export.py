#!/usr/bin/env python3
"""
standalone_export.py - 无需打开 IDA GUI，直接在命令行导出二进制文件的全部分析数据

用法:
    python standalone_export.py <binary_file> [options]

示例:
    python standalone_export.py /path/to/binary
    python standalone_export.py /path/to/binary -o /path/to/output
    python standalone_export.py /path/to/binary --skip-analysis
    python standalone_export.py /path/to/binary --idadir /opt/ida-pro-9.3

依赖:
    - idapro (IDA idalib Python 包，需要 IDA Pro 9.0+ 或配置好 idalib 的环境)
"""

import os
import sys
import argparse
import gc
import glob
import multiprocessing as mp


# ---------------------------------------------------------------------------
# 自动检测 IDA 安装目录
# ---------------------------------------------------------------------------
DEFAULT_IDA_SEARCH_PATHS = [
    os.path.expanduser("~/ida-pro-9.3"),
    os.path.expanduser("~/ida-pro-9.2"),
    os.path.expanduser("~/ida-pro-9.1"),
    os.path.expanduser("~/ida-pro-9.0"),
    os.path.expanduser("~/ida"),
    "/opt/ida-pro-9.3",
    "/opt/ida-pro-9.2",
    "/opt/ida-pro-9.1",
    "/opt/ida-pro-9.0",
    "/opt/ida",
]


def find_ida_dir():
    """自动搜索 IDA 安装目录（通过 libidalib.so 判断）"""
    # 优先使用环境变量
    env_dir = os.environ.get("IDADIR")
    if env_dir and os.path.isfile(os.path.join(env_dir, "libidalib.so")):
        return env_dir

    # 搜索常见路径
    for path in DEFAULT_IDA_SEARCH_PATHS:
        if os.path.isfile(os.path.join(path, "libidalib.so")):
            return path

    return None


def setup_ida_env(ida_dir):
    """设置 IDA 运行所需的环境变量和 Python 路径"""
    os.environ["IDADIR"] = ida_dir

    # 更新 idapro 配置文件（~/.idapro/ida-config.json）
    try:
        import json
        config_dir = os.path.expanduser("~/.idapro")
        config_path = os.path.join(config_dir, "ida-config.json")
        os.makedirs(config_dir, exist_ok=True)
        config = {}
        if os.path.isfile(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
        if "Paths" not in config:
            config["Paths"] = {}
        config["Paths"]["ida-install-dir"] = ida_dir
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print("[!] Warning: failed to update idapro config: {}".format(e))

    # 将 IDA 的 python 目录加入 sys.path，确保能找到 ida_* 模块
    ida_python_dir = os.path.join(ida_dir, "python")
    ida_python3_dir = os.path.join(ida_dir, "python3")

    for p in [ida_python_dir, ida_python3_dir]:
        if os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)

    # 将 IDA 根目录也加入路径（idapro 可能需要）
    if ida_dir not in sys.path:
        sys.path.insert(0, ida_dir)


# ---------------------------------------------------------------------------
# idalib 初始化：必须在所有 ida_* 模块之前 import idapro
# ---------------------------------------------------------------------------

# 解析 --idadir 参数（在 argparse 之前手动提取，因为 idapro import 需要尽早设置）
_idadir_arg = None
for i, arg in enumerate(sys.argv):
    if arg == "--idadir" and i + 1 < len(sys.argv):
        _idadir_arg = sys.argv[i + 1]
        break

if _idadir_arg:
    if not os.path.isfile(os.path.join(_idadir_arg, "libidalib.so")):
        print("[!] 指定的 --idadir 目录无效，未找到 libidalib.so: {}".format(_idadir_arg))
        sys.exit(1)
    setup_ida_env(_idadir_arg)
else:
    _detected_dir = find_ida_dir()
    if _detected_dir:
        print("[*] 自动检测到 IDA 安装目录: {}".format(_detected_dir))
        setup_ida_env(_detected_dir)
    else:
        print("[!] 未找到 IDA 安装目录。请通过以下任一方式指定：")
        print("    1. 设置环境变量: export IDADIR=/path/to/ida-pro-9.3")
        print("    2. 命令行参数: python standalone_export.py <binary> --idadir /path/to/ida-pro-9.3")
        sys.exit(1)

import idapro

import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import ida_lines
import ida_auto
import ida_idaapi
import ida_ida
import ida_idp


WORKER_COUNT = max(1, mp.cpu_count() - 1)


# ===========================================================================
# 工具函数（从 INP.py 移植，去掉 ida_kernwin / ida_undo 依赖）
# ===========================================================================

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def clear_undo_buffer():
    gc.collect()


def get_callers(func_ea):
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))


def get_callees(func_ea):
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))


def format_address_list(addr_list):
    return ", ".join([hex(addr) for addr in addr_list])


def get_function_output_filename(func_ea, export_type):
    if export_type == "disassembly-fallback":
        return "{:X}.asm".format(func_ea)
    return "{:X}.c".format(func_ea)


def get_function_output_subdir(export_type):
    if export_type == "disassembly-fallback":
        return "disassembly"
    return "decompile"


def get_function_output_relative_path(func_ea, export_type):
    return "{}/{}".format(
        get_function_output_subdir(export_type),
        get_function_output_filename(func_ea, export_type),
    )


def get_function_output_path(export_dir, func_ea, export_type):
    output_dir = os.path.join(export_dir, get_function_output_subdir(export_type))
    output_filename = get_function_output_filename(func_ea, export_type)
    return os.path.join(output_dir, output_filename)


def find_existing_function_output(export_dir, func_ea):
    for export_type in ("decompile", "disassembly-fallback"):
        output_path = get_function_output_path(export_dir, func_ea, export_type)
        if os.path.exists(output_path):
            return get_function_output_relative_path(func_ea, export_type), output_path
    return None, None


def build_function_output_lines(func_ea, func_name, source_type, callers, callees, body, fallback_reason=None):
    lines = []
    lines.append("/*")
    lines.append(" * func-name: {}".format(func_name))
    lines.append(" * func-address: {}".format(hex(func_ea)))
    lines.append(" * export-type: {}".format(source_type))
    lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
    lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
    if fallback_reason:
        lines.append(" * fallback-reason: {}".format(fallback_reason))
    lines.append(" */")
    lines.append("")
    lines.append(body)
    return lines


def generate_function_disassembly(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None, "not a valid function"
    disasm_lines = []
    for item_ea in idautils.FuncItems(func_ea):
        disasm_line = ida_lines.generate_disasm_line(
            item_ea, ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS
        )
        if disasm_line is None:
            disasm_line = ""
        else:
            disasm_line = ida_lines.tag_remove(disasm_line).rstrip()
        if not disasm_line:
            disasm_line = "<unable to render disassembly>"
        disasm_lines.append("{:X}: {}".format(item_ea, disasm_line))
    if not disasm_lines:
        return None, "function has no items"
    return "\n".join(disasm_lines), None


def save_progress(export_dir, processed_addrs, fallback_funcs, failed_funcs, skipped_funcs):
    progress_file = os.path.join(export_dir, ".export_progress")
    try:
        with open(progress_file, "w", encoding="utf-8") as f:
            f.write("# Export Progress\n")
            f.write("# Format: address | status (done/fallback/failed/skipped)\n")
            for addr in processed_addrs:
                f.write("{:X}|done\n".format(addr))
            for addr, name, reason, output_filename in fallback_funcs:
                f.write("{:X}|fallback|{}|{}|{}\n".format(addr, name, reason, output_filename))
            for addr, name, reason in failed_funcs:
                f.write("{:X}|failed|{}|{}\n".format(addr, name, reason))
            for addr, name, reason in skipped_funcs:
                f.write("{:X}|skipped|{}|{}\n".format(addr, name, reason))
    except Exception as e:
        print("[!] Failed to save progress: {}".format(str(e)))


def load_progress(export_dir):
    progress_file = os.path.join(export_dir, ".export_progress")
    processed = set()
    fallback = []
    failed = []
    skipped = []
    if not os.path.exists(progress_file):
        return processed, fallback, failed, skipped
    try:
        with open(progress_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) >= 2:
                    addr = int(parts[0], 16)
                    status = parts[1]
                    if status == "done":
                        processed.add(addr)
                    elif status == "fallback" and len(parts) >= 5:
                        fallback.append((addr, parts[2], parts[3], parts[4]))
                    elif status == "failed" and len(parts) >= 4:
                        failed.append((addr, parts[2], parts[3]))
                    elif status == "skipped" and len(parts) >= 4:
                        skipped.append((addr, parts[2], parts[3]))
        print("[+] Loaded progress: {} functions already processed".format(len(processed)))
    except Exception as e:
        print("[!] Failed to load progress: {}".format(str(e)))
    return processed, fallback, failed, skipped


# ===========================================================================
# 核心导出函数
# ===========================================================================


def export_decompiled_functions(export_dir, skip_existing=True):
    decompile_dir = os.path.join(export_dir, "decompile")
    disassembly_dir = os.path.join(export_dir, "disassembly")
    ensure_dir(decompile_dir)
    ensure_dir(disassembly_dir)

    total_funcs = 0
    exported_funcs = 0
    fallback_funcs = []
    failed_funcs = []
    skipped_funcs = []
    function_index = []
    addr_to_info = {}

    processed_addrs, prev_fallback, prev_failed, prev_skipped = load_progress(export_dir)
    fallback_funcs.extend(prev_fallback)
    failed_funcs.extend(prev_failed)
    skipped_funcs.extend(prev_skipped)

    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    remaining_funcs = [ea for ea in all_funcs if ea not in processed_addrs]

    print("[*] Found {} functions total, {} remaining to process".format(total_funcs, len(remaining_funcs)))

    if not remaining_funcs:
        print("[+] All functions already exported!")
        return

    BATCH_SIZE = 10
    MEMORY_CLEAN_INTERVAL = 5

    def write_function_file(args):
        func_ea, func_name, body, callers, callees, export_type, fallback_reason = args
        output_lines = build_function_output_lines(
            func_ea, func_name, export_type, callers, callees, body, fallback_reason=fallback_reason
        )
        output_filename = get_function_output_relative_path(func_ea, export_type)
        output_path = get_function_output_path(export_dir, func_ea, export_type)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(output_lines))
            return func_ea, func_name, True, output_filename, callers, callees, export_type, fallback_reason, None
        except IOError as e:
            return func_ea, func_name, False, output_filename, callers, callees, export_type, fallback_reason, str(e)

    def aggressive_memory_cleanup():
        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass
        gc.collect()
        gc.collect()

    # 使用简单的线程池做 I/O
    from concurrent.futures import ThreadPoolExecutor
    io_executor = ThreadPoolExecutor(max_workers=1)
    pending_writes = []

    for idx, func_ea in enumerate(remaining_funcs):
        func_name = idc.get_func_name(func_ea)
        func = ida_funcs.get_func(func_ea)
        if func is None:
            skipped_funcs.append((func_ea, func_name, "not a valid function"))
            processed_addrs.add(func_ea)
            continue
        if func.flags & ida_funcs.FUNC_LIB:
            skipped_funcs.append((func_ea, func_name, "library function"))
            processed_addrs.add(func_ea)
            continue

        output_body = None
        export_type = None
        fallback_reason = None
        dec_obj = None

        try:
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                fallback_reason = "decompile returned None"
            else:
                dec_str = str(dec_obj)
                dec_obj = None
                if dec_str and len(dec_str.strip()) > 0:
                    output_body = dec_str
                    export_type = "decompile"
                else:
                    fallback_reason = "empty decompilation result"
        except ida_hexrays.DecompilationFailure as e:
            fallback_reason = "decompilation failure: {}".format(str(e))
        except Exception as e:
            fallback_reason = "unexpected error: {}".format(str(e))
            print("[!] Error decompiling {} at {}: {}".format(func_name, hex(func_ea), str(e)))
        finally:
            dec_obj = None

        if output_body is None:
            output_body, disasm_error = generate_function_disassembly(func_ea)
            if output_body is None:
                combined_reason = fallback_reason or "unknown decompilation error"
                if disasm_error:
                    combined_reason = "{}; disassembly fallback failed: {}".format(combined_reason, disasm_error)
                failed_funcs.append((func_ea, func_name, combined_reason))
                processed_addrs.add(func_ea)
                continue
            export_type = "disassembly-fallback"

        callers = get_callers(func_ea)
        callees = get_callees(func_ea)

        existing_output_filename, _ = find_existing_function_output(export_dir, func_ea)
        if skip_existing and existing_output_filename:
            exported_funcs += 1
            processed_addrs.add(func_ea)
            if (exported_funcs + len(prev_fallback) + len(prev_failed) + len(prev_skipped)) % 100 == 0:
                print(
                    "[+] Exported {} / {} functions...".format(
                        exported_funcs + len(prev_fallback) + len(prev_failed) + len(prev_skipped), total_funcs
                    )
                )
            continue

        output_filename = get_function_output_relative_path(func_ea, export_type)
        write_args = (func_ea, func_name, output_body, callers, callees, export_type, fallback_reason)
        future = io_executor.submit(write_function_file, write_args)
        pending_writes.append((future, func_ea, func_name, output_filename, callers, callees, export_type, fallback_reason))
        output_body = None

        if (idx + 1) % MEMORY_CLEAN_INTERVAL == 0:
            clear_undo_buffer()
            aggressive_memory_cleanup()

        if len(pending_writes) >= BATCH_SIZE:
            for f, fea, fn, ofn, ca, ce, et, fr in pending_writes:
                try:
                    r = f.result()
                    _process_write_result(r, function_index, addr_to_info, fallback_funcs, failed_funcs, processed_addrs, exported_funcs)
                except Exception as e:
                    print("[!] Write error: {}".format(str(e)))
            save_progress(export_dir, processed_addrs, fallback_funcs, failed_funcs, skipped_funcs)
            pending_writes = []
            aggressive_memory_cleanup()

    if pending_writes:
        for f, fea, fn, ofn, ca, ce, et, fr in pending_writes:
            try:
                r = f.result()
                _process_write_result(r, function_index, addr_to_info, fallback_funcs, failed_funcs, processed_addrs, exported_funcs)
            except Exception as e:
                print("[!] Write error: {}".format(str(e)))

    io_executor.shutdown(wait=True)
    save_progress(export_dir, processed_addrs, fallback_funcs, failed_funcs, skipped_funcs)

    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Fallback to disassembly: {}".format(len(fallback_funcs)))
    print("    Skipped: {} (library/invalid functions)".format(len(skipped_funcs)))
    print("    Failed: {}".format(len(failed_funcs)))

    if fallback_funcs:
        fallback_log_path = os.path.join(export_dir, "disassembly_fallback.txt")
        with open(fallback_log_path, "w", encoding="utf-8") as f:
            f.write("# Fallback to disassembly for {} functions\n".format(len(fallback_funcs)))
            f.write("# Format: address | function_name | reason | output_file\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason, output_filename in fallback_funcs:
                f.write("{} | {} | {} | {}\n".format(hex(addr), name, reason, output_filename))
        print("    Fallback list saved to: disassembly_fallback.txt")

    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, "w", encoding="utf-8") as f:
            f.write("# Failed to decompile {} functions\n".format(len(failed_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in failed_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

    if skipped_funcs:
        skipped_log_path = os.path.join(export_dir, "decompile_skipped.txt")
        with open(skipped_log_path, "w", encoding="utf-8") as f:
            f.write("# Skipped {} functions\n".format(len(skipped_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in skipped_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Skipped list saved to: decompile_skipped.txt")

    if function_index:
        index_path = os.path.join(export_dir, "function_index.txt")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write("# Function Index\n")
            f.write("# Total exported functions: {}\n".format(len(function_index)))
            f.write("#" + "=" * 80 + "\n\n")
            for func_info in function_index:
                f.write("=" * 80 + "\n")
                f.write("Function: {}\n".format(func_info["name"]))
                f.write("Address: {}\n".format(hex(func_info["address"])))
                f.write("File: {}\n".format(func_info["filename"]))
                f.write("Type: {}\n".format(func_info["export_type"]))
                if "fallback_reason" in func_info:
                    f.write("Fallback reason: {}\n".format(func_info["fallback_reason"]))
                f.write("\n")
                if func_info["callers"]:
                    f.write("Called by ({} callers):\n".format(len(func_info["callers"])))
                    for caller_addr in func_info["callers"]:
                        if caller_addr in addr_to_info:
                            ci = addr_to_info[caller_addr]
                            f.write("  - {} ({}) -> {}\n".format(hex(caller_addr), ci["name"], ci["filename"]))
                        else:
                            f.write("  - {} ({})\n".format(hex(caller_addr), idc.get_func_name(caller_addr)))
                else:
                    f.write("Called by: none\n")
                f.write("\n")
                if func_info["callees"]:
                    f.write("Calls ({} callees):\n".format(len(func_info["callees"])))
                    for callee_addr in func_info["callees"]:
                        if callee_addr in addr_to_info:
                            ci = addr_to_info[callee_addr]
                            f.write("  - {} ({}) -> {}\n".format(hex(callee_addr), ci["name"], ci["filename"]))
                        else:
                            f.write("  - {} ({})\n".format(hex(callee_addr), idc.get_func_name(callee_addr)))
                else:
                    f.write("Calls: none\n")
                f.write("\n")
        print("    Function index saved to: function_index.txt")


def _process_write_result(result, function_index, addr_to_info, fallback_funcs, failed_funcs, processed_addrs, exported_funcs):
    func_ea, func_name, success, output_filename, callers, callees, export_type, fallback_reason, error = result
    if success:
        func_info = {
            "address": func_ea,
            "name": func_name,
            "filename": output_filename,
            "export_type": export_type,
            "callers": callers,
            "callees": callees,
        }
        if fallback_reason:
            func_info["fallback_reason"] = fallback_reason
        function_index.append(func_info)
        addr_to_info[func_ea] = func_info
        if export_type == "disassembly-fallback":
            fallback_funcs.append((func_ea, func_name, fallback_reason or "decompilation failed", output_filename))
        exported_funcs += 1
        processed_addrs.add(func_ea)
    else:
        failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
        processed_addrs.add(func_ea)


def export_strings(export_dir):
    strings_path = os.path.join(export_dir, "strings.txt")
    string_count = 0
    with open(strings_path, "w", encoding="utf-8") as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")
        for s in idautils.Strings():
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                f.write(
                    "{} | {} | {} | {}\n".format(
                        hex(s.ea), s.length, str_type, string_content.replace("\n", "\\n").replace("\r", "\\r")
                    )
                )
                string_count += 1
            except Exception:
                continue
    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))


def export_imports(export_dir):
    imports_path = os.path.join(export_dir, "imports.txt")
    import_count = 0
    with open(imports_path, "w", encoding="utf-8") as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)

            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True

            ida_nalt.enum_import_names(i, imp_cb)
    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))


def export_exports(export_dir):
    exports_path = os.path.join(export_dir, "exports.txt")
    export_count = 0
    with open(exports_path, "w", encoding="utf-8") as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1
    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))


def export_memory(export_dir):
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)
    CHUNK_SIZE = 1 * 1024 * 1024
    BYTES_PER_LINE = 16
    total_bytes = 0
    file_count = 0
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)
        print("[*] Processing segment: {} ({} - {})".format(seg_name, hex(seg_start), hex(seg_end)))
        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)
            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)
            if os.path.exists(filepath):
                file_count += 1
                current_addr = chunk_end
                total_bytes += chunk_end - current_addr
                continue
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")
                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break
                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue
                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining
                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."
                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))
                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)
            file_count += 1
            current_addr = chunk_end
            clear_undo_buffer()
    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024 * 1024)))
    print("    Files created: {}".format(file_count))


# ===========================================================================
# 指针导出
# ===========================================================================


def _ptr_get_ptr_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def _ptr_read_pointer(ea, ptr_size):
    return ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)


def _ptr_get_segment_name(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return "unknown"
    name = ida_segment.get_segm_name(seg)
    return name if name else "unknown"


def _ptr_is_valid_target(target_ea):
    if target_ea in (0, ida_idaapi.BADADDR):
        return False
    return ida_segment.getseg(target_ea) is not None


def _ptr_safe_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            value = repr(value)
    else:
        value = str(value)
    value = value.replace("\r", " ").replace("\n", " ").replace("|", "/").strip()
    if len(value) > 80:
        value = value[:77] + "..."
    return value


def _ptr_get_target_name(target_ea):
    name = idc.get_name(target_ea, idc.GN_VISIBLE)
    if not name:
        func = ida_funcs.get_func(target_ea)
        if func:
            name = idc.get_func_name(func.start_ea)
    if not name:
        name = "unknown"
    return _ptr_safe_text(name)


def _ptr_try_get_string_preview(target_ea):
    try:
        flags = ida_bytes.get_full_flags(target_ea)
        if not ida_bytes.is_strlit(flags):
            return ""
    except Exception:
        return ""
    try:
        strtype = idc.get_str_type(target_ea)
    except Exception:
        strtype = -1
    try:
        raw = ida_bytes.get_strlit_contents(target_ea, -1, strtype)
    except Exception:
        raw = None
    preview = _ptr_safe_text(raw)
    if preview:
        return '"{}"'.format(preview)
    return "string_literal"


def _ptr_is_import_target(target_ea, target_name):
    seg_name = _ptr_get_segment_name(target_ea).lower()
    name_l = (target_name or "").lower()
    if name_l.startswith("__imp_") or name_l.startswith("imp_"):
        return True
    import_like_segments = {
        "extern", ".idata", "idata", ".idata$2", ".idata$4", ".idata$5", ".idata$6",
        ".got", "got", ".got.plt", "got.plt", "__la_symbol_ptr", "__nl_symbol_ptr",
    }
    return seg_name in import_like_segments


def _ptr_classify_target(target_ea):
    target_name = _ptr_get_target_name(target_ea)
    try:
        flags = ida_bytes.get_full_flags(target_ea)
    except Exception:
        flags = 0
    if _ptr_is_import_target(target_ea, target_name):
        return target_name, "import_pointer", "import_entry"
    try:
        if ida_bytes.is_strlit(flags):
            return target_name, "string_pointer", _ptr_try_get_string_preview(target_ea)
    except Exception:
        pass
    try:
        func = ida_funcs.get_func(target_ea)
    except Exception:
        func = None
    if func:
        if func.start_ea == target_ea:
            return target_name, "function_pointer", "function_start"
        func_name = _ptr_get_target_name(func.start_ea)
        return target_name, "code_pointer", "inside_{}".format(func_name)
    try:
        if ida_bytes.is_code(flags):
            return target_name, "code_pointer", "instruction"
    except Exception:
        pass
    try:
        if ida_bytes.is_struct(flags):
            return target_name, "struct_pointer", "struct_data"
    except Exception:
        pass
    try:
        if ida_bytes.is_data(flags):
            return target_name, "data_pointer", "data_item_size={}".format(ida_bytes.get_item_size(target_ea))
    except Exception:
        pass
    return target_name, "unknown_pointer", ""


def _ptr_add_record(records, seen, source_ea, target_ea):
    key = (source_ea, target_ea)
    if key in seen:
        return
    seen.add(key)
    target_name, target_type, target_detail = _ptr_classify_target(target_ea)
    records.append(
        {
            "source_addr": source_ea,
            "source_seg": _ptr_get_segment_name(source_ea),
            "points_to": target_ea,
            "target_name": target_name,
            "target_type": target_type,
            "target_detail": target_detail,
        }
    )


def _ptr_collect_data_xrefs(records, seen):
    total = 0
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if not seg:
            continue
        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue
            if not ida_bytes.is_head(flags):
                continue
            if not (ida_bytes.is_code(flags) or ida_bytes.is_data(flags)):
                continue
            try:
                target = ida_xref.get_first_dref_from(head)
            except Exception:
                target = ida_idaapi.BADADDR
            while target != ida_idaapi.BADADDR:
                if _ptr_is_valid_target(target):
                    _ptr_add_record(records, seen, head, target)
                    total += 1
                try:
                    target = ida_xref.get_next_dref_from(head, target)
                except Exception:
                    break
    return total


def _ptr_collect_raw_pointers(records, seen, ptr_size):
    total = 0
    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        seg_start = idc.get_segm_start(seg_ea)
        seg_end = idc.get_segm_end(seg_ea)
        if not seg_name or not (seg_name.startswith(".data") or seg_name.startswith(".rdata") or seg_name.startswith("data")):
            continue
        print("[*] Scanning segment: {} ({:X} - {:X})".format(seg_name, seg_start, seg_end))
        for head in idautils.Heads(seg_start, seg_end):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue
            if not ida_bytes.is_head(flags):
                continue
            if not ida_bytes.is_data(flags):
                continue
            try:
                item_size = ida_bytes.get_item_size(head)
            except Exception:
                item_size = 0
            if item_size < ptr_size:
                continue
            slot_count = item_size // ptr_size
            if slot_count <= 0:
                continue
            for i in range(slot_count):
                slot_ea = head + i * ptr_size
                try:
                    target = _ptr_read_pointer(slot_ea, ptr_size)
                except Exception:
                    continue
                if _ptr_is_valid_target(target):
                    _ptr_add_record(records, seen, slot_ea, target)
                    total += 1
    return total


def export_pointers(export_dir):
    output_path = os.path.join(export_dir, "pointers.txt")
    ptr_size = _ptr_get_ptr_size()
    records = []
    seen = set()
    print("[*] Starting pointer scan. Pointer size: {} bytes".format(ptr_size))
    dref_hits = _ptr_collect_data_xrefs(records, seen)
    raw_hits = _ptr_collect_raw_pointers(records, seen, ptr_size)
    records.sort(
        key=lambda item: (
            item["source_addr"],
            item["points_to"],
            item["source_seg"],
            item["target_name"],
            item["target_type"],
            item["target_detail"],
        )
    )
    if records:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("# Total Pointers Found: {}\n".format(len(records)))
                f.write("# Format: Source_Address | Segment | Points_To_Address | Target_Name | Target_Type | Target_Detail\n")
                f.write("# Pointer size: {}\n".format(ptr_size))
                f.write("# Data xref hits: {}\n".format(dref_hits))
                f.write("# Raw pointer hits: {}\n".format(raw_hits))
                f.write("-" * 120 + "\n")
                for p in records:
                    f.write(
                        "{:X} | {} | {:X} | {} | {} | {}\n".format(
                            p["source_addr"],
                            p["source_seg"],
                            p["points_to"],
                            p["target_name"],
                            p["target_type"],
                            p["target_detail"],
                        )
                    )
            print("[+] Pointers exported to: {}".format(output_path))
            print("[*] Pointers Summary:")
            print("    Data xref hits: {}".format(dref_hits))
            print("    Raw pointer hits: {}".format(raw_hits))
            print("    Unique pointer references exported: {}".format(len(records)))
        except Exception as e:
            print("[!] Failed to write pointers: {}".format(str(e)))
    else:
        print("[*] No pointers found or no data segments scanned.")


# ===========================================================================
# 主入口
# ===========================================================================


def do_export(binary_path, export_dir=None, skip_analysis=False):
    """执行导出

    Args:
        binary_path: 要分析的二进制文件路径
        export_dir: 输出目录，默认为二进制文件同目录下的 export-for-ai
        skip_analysis: 是否跳过自动分析（如果已有 .i64/.idb 数据库可跳过）
    """
    binary_path = os.path.abspath(binary_path)
    if not os.path.isfile(binary_path):
        print("[!] File not found: {}".format(binary_path))
        sys.exit(1)

    if export_dir is None:
        export_dir = os.path.join(os.path.dirname(binary_path), "export-for-ai")
    export_dir = os.path.abspath(export_dir)
    ensure_dir(export_dir)

    print("=" * 60)
    print("IDA Standalone Export for AI Analysis")
    print("=" * 60)
    print("[*] Binary: {}".format(binary_path))
    print("[*] Output: {}".format(export_dir))

    # ---- 使用 idapro 打开数据库 ----
    print("[*] Opening database with idapro...")
    run_analysis = not skip_analysis
    err = idapro.open_database(binary_path, run_auto_analysis=run_analysis)
    if err:
        print("[!] Failed to open database: {}".format(err))
        sys.exit(1)
    print("[+] Database opened")

    # 等待自动分析完成
    if run_analysis:
        print("[*] Waiting for auto-analysis to complete...")
        ida_auto.auto_wait()
        print("[+] Auto-analysis completed")

    # 初始化 Hex-Rays
    has_hexrays = False
    try:
        if ida_hexrays.init_hexrays_plugin():
            has_hexrays = True
            print("[+] Hex-Rays decompiler initialized")
        else:
            print("[!] Hex-Rays decompiler not available")
    except Exception as e:
        print("[!] Hex-Rays init failed: {}".format(e))

    # ---- 导出各部分 ----
    print("\n[*] Exporting strings...")
    export_strings(export_dir)
    print("")

    print("[*] Exporting imports...")
    export_imports(export_dir)
    print("")

    print("[*] Exporting exports...")
    export_exports(export_dir)
    print("")

    print("[*] Exporting pointers...")
    export_pointers(export_dir)
    print("")

    print("[*] Exporting memory...")
    export_memory(export_dir)
    print("")

    if has_hexrays:
        print("[*] Exporting decompiled functions with disassembly fallback...")
        export_decompiled_functions(export_dir, skip_existing=True)

    # 关闭数据库
    print("\n[*] Closing database...")
    idapro.close_database()

    print("")
    print("=" * 60)
    print("[+] Export completed!")
    print("    Output directory: {}".format(export_dir))
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="无需 IDA GUI，直接在命令行导出二进制文件分析数据（需要 idalib）"
    )
    parser.add_argument("binary", help="要分析的二进制文件路径")
    parser.add_argument("-o", "--output", default=None, help="输出目录 (默认: <binary所在目录>/export-for-ai)")
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="跳过自动分析 (如果已有 .i64/.idb 数据库可使用此选项加速)",
    )
    parser.add_argument(
        "--idadir",
        default=None,
        help="指定 IDA 安装目录 (默认自动检测)",
    )
    args = parser.parse_args()
    do_export(args.binary, export_dir=args.output, skip_analysis=args.skip_analysis)


if __name__ == "__main__":
    main()
