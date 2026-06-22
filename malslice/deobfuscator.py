"""§4.5 Deobfuscator（按 obf_class 路由的工具链）。

实现要点：
- Python AST 常量链（b64_chain / hex_chain / zlib_chain）在此完整实现，
  以 exec/eval 的参数为起点反向解析常量表达式链。
- JS eval_string：对切片内 `eval(atob("..."))` / `Function("...")` / `eval("lit")`
  做局部 AST 折叠，写回 .deob.js。
- 其他 obf_class（pyarmor、pyc_marshal、jsobf_stringarray、webpack_bundle、jsfuck、aaencode）
  需外部工具，这里只记录 deob_tool="failed"，由 §7 兜底 F 接管。
"""
from __future__ import annotations

import ast
import base64
import binascii
import codecs
import os
import re
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .utils import shannon_entropy, max_line_length


@dataclass
class DeobResult:
    success: bool
    tool: str                         # webcrack / synchrony / ast_const_chain / ...
    output_rel: Optional[str]         # 相对 extract_dir 的路径，如 deobf/foo.deob.py
    reason: str = ""


PY_DECODERS_CHAIN: Dict[str, str] = {
    "base64.b64decode": "b64decode",
    "base64.b32decode": "b32decode",
    "base64.b16decode": "b16decode",
    "base64.urlsafe_b64decode": "b64decode_url",
    "codecs.decode": "codecs_decode",
    "bytes.fromhex": "fromhex",
    "zlib.decompress": "zlib_decompress",
    "gzip.decompress": "gzip_decompress",
    "lzma.decompress": "lzma_decompress",
}


def _collect_py_aliases(tree: ast.AST) -> Dict[str, str]:
    from .slicer_py import collect_alias_map
    return collect_alias_map(tree)


def _resolve_qname_py(node: ast.AST, alias_map: Dict[str, str]) -> Optional[str]:
    from .slicer_py import resolve_qualified_name
    return resolve_qualified_name(node, alias_map)


def _try_eval_const_chain(node: ast.AST, alias_map: Dict[str, str]) -> Optional[str]:
    """尝试静态求值一个常量解码链。成功返回 decoded 字符串。

    支持：
      - Constant 字符串/字节
      - 函数调用 f(x) / f(x, y)，f 在 PY_DECODERS_CHAIN 中
      - 右操作数为常量的二元表达式（简单拼接）
    """
    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, (str, bytes)):
            return v if isinstance(v, str) else v.decode("latin-1", errors="replace")
        return None

    if isinstance(node, ast.Call):
        qname = _resolve_qname_py(node, alias_map) or ""
        # 兼容短名调用：b64decode(...) / fromhex(...) 等
        short_map = {
            "b64decode": "base64.b64decode",
            "b32decode": "base64.b32decode",
            "b16decode": "base64.b16decode",
            "urlsafe_b64decode": "base64.urlsafe_b64decode",
            "fromhex": "bytes.fromhex",
            "decompress": None,  # 无法确定来源
        }
        if qname in short_map and short_map[qname]:
            qname = short_map[qname]
        if qname not in PY_DECODERS_CHAIN:
            return None
        if not node.args:
            return None
        arg0 = _try_eval_const_chain(node.args[0], alias_map)
        if arg0 is None:
            return None
        tag = PY_DECODERS_CHAIN[qname]
        try:
            if tag in ("b64decode", "b64decode_url"):
                b = arg0.encode() if isinstance(arg0, str) else arg0
                decoded = base64.b64decode(b)
                return decoded.decode("utf-8", errors="replace")
            if tag == "b32decode":
                return base64.b32decode(arg0.encode()).decode("utf-8", errors="replace")
            if tag == "b16decode":
                return base64.b16decode(arg0.encode()).decode("utf-8", errors="replace")
            if tag == "codecs_decode":
                enc = "hex"
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    enc = node.args[1].value
                if enc == "hex":
                    return bytes.fromhex(arg0.strip()).decode("utf-8", errors="replace")
                if enc in ("rot_13", "rot13"):
                    return codecs.decode(arg0, "rot_13")
                if enc in ("base64", "base64_codec"):
                    return base64.b64decode(arg0.encode()).decode("utf-8", errors="replace")
                return codecs.decode(arg0.encode(), enc).decode("utf-8", errors="replace") if isinstance(arg0, str) else None
            if tag == "fromhex":
                return bytes.fromhex(arg0.strip()).decode("utf-8", errors="replace")
            if tag == "zlib_decompress":
                b = arg0.encode("latin-1") if isinstance(arg0, str) else arg0
                return zlib.decompress(b).decode("utf-8", errors="replace")
            if tag == "gzip_decompress":
                import gzip
                b = arg0.encode("latin-1") if isinstance(arg0, str) else arg0
                return gzip.decompress(b).decode("utf-8", errors="replace")
            if tag == "lzma_decompress":
                import lzma
                b = arg0.encode("latin-1") if isinstance(arg0, str) else arg0
                return lzma.decompress(b).decode("utf-8", errors="replace")
        except (binascii.Error, zlib.error, ValueError, OSError, Exception):
            return None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _try_eval_const_chain(node.left, alias_map)
        right = _try_eval_const_chain(node.right, alias_map)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        return None

    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                return None
        return "".join(parts)

    return None


class _ExecUnfolder(ast.NodeTransformer):
    """替换 exec(<constant_chain>) / eval(<constant_chain>) 为显式 exec(<decoded_str>)。"""

    def __init__(self, alias_map: Dict[str, str]):
        self.alias_map = alias_map
        self.replaced_count = 0

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        qname = _resolve_qname_py(node, self.alias_map) or ""
        if qname in ("exec", "eval", "builtins.exec", "builtins.eval") and node.args:
            decoded = _try_eval_const_chain(node.args[0], self.alias_map)
            if decoded is not None:
                new_node = ast.Call(
                    func=node.func,
                    args=[ast.Constant(value=decoded)] + list(node.args[1:]),
                    keywords=node.keywords,
                )
                ast.copy_location(new_node, node)
                ast.fix_missing_locations(new_node)
                self.replaced_count += 1
                return new_node
        return node


def deobfuscate_python_file(source: str) -> Tuple[Optional[str], int]:
    """对整个 py 源做 exec/eval 常量链还原。返回 (new_source, replaced_count)。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None, 0
    alias_map = _collect_py_aliases(tree)
    trans = _ExecUnfolder(alias_map)
    new_tree = trans.visit(tree)
    ast.fix_missing_locations(new_tree)
    if trans.replaced_count == 0:
        return None, 0
    try:
        return ast.unparse(new_tree), trans.replaced_count
    except Exception:
        return None, 0


# ----------------------------------------------------------------------
# JS eval_string 折叠（简易版）
# ----------------------------------------------------------------------

EVAL_ATOB_RE = re.compile(
    r"""\beval\s*\(\s*atob\s*\(\s*(['"])([A-Za-z0-9+/=]+)\1\s*\)\s*\)""",
    re.DOTALL,
)
FUNCTION_STR_RE = re.compile(
    r"""\bFunction\s*\(\s*(['"])(.*?)\1\s*\)\s*\(\s*\)""", re.DOTALL,
)
EVAL_LITERAL_RE = re.compile(
    r"""\beval\s*\(\s*(['"`])(.*?)\1\s*\)""", re.DOTALL,
)

# --- 增强 1：裸 atob 折叠，如  atob("cHJpbnQ=")  ---
ATOB_BARE_RE = re.compile(
    r"""\batob\s*\(\s*(['"])([A-Za-z0-9+/=]{8,})\1\s*\)""",
    re.DOTALL,
)

# --- 增强 2：String.fromCharCode(72,101,108,108,111) → "Hello" ---
FROM_CHARCODE_RE = re.compile(
    r"""\bString\.fromCharCode\s*\(\s*([0-9, \t\r\n]+)\)""",
    re.DOTALL,
)

# --- 增强 3：Buffer.from("aGVsbG8=", "base64") / Buffer.from("68656c6c6f", "hex") ---
BUFFER_FROM_RE = re.compile(
    r"""\bBuffer\.from\s*\(\s*(['"])([A-Za-z0-9+/=]+)\1\s*,\s*(['"])(base64|hex)\3\s*\)""",
    re.DOTALL,
)

# --- 增强 4：纯 hex-escape 字符串字面量（"\x48\x65\x6c..."），长度 ≥ 16 时才折叠，
# 以免误伤正常 unicode 转义 ---
HEX_ESCAPE_STR_RE = re.compile(
    r"""(['"])((?:\\x[0-9a-fA-F]{2}){8,})\1""",
    re.DOTALL,
)


def deobfuscate_js_eval_string(source: str) -> Tuple[Optional[str], int]:
    """处理 eval(atob()) / Function() / eval(lit) / 裸 atob / fromCharCode / Buffer.from /
    纯 hex-escape 字符串 等常见 JS payload 变形。"""
    replaced = 0

    def _repl_atob_in_eval(m: re.Match) -> str:
        nonlocal replaced
        payload = m.group(2)
        try:
            decoded = base64.b64decode(payload.encode()).decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)
        replaced += 1
        return f"/* decoded eval(atob()) */\n{decoded}\n"

    def _repl_atob_bare(m: re.Match) -> str:
        nonlocal replaced
        payload = m.group(2)
        try:
            decoded = base64.b64decode(payload.encode()).decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)
        # 若解出的内容都是可打印 ASCII，才做替换；否则放弃（防止误伤随机 base64）
        printable_ratio = sum(1 for c in decoded if 32 <= ord(c) < 127 or c in "\n\r\t") / max(len(decoded), 1)
        if printable_ratio < 0.85:
            return m.group(0)
        replaced += 1
        safe = decoded.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{safe}" /* <-- atob */'

    def _repl_fn(m: re.Match) -> str:
        nonlocal replaced
        replaced += 1
        body = m.group(2).encode().decode("unicode_escape", errors="replace")
        return f"/* decoded Function() */\n{body}\n"

    def _repl_eval_lit(m: re.Match) -> str:
        nonlocal replaced
        replaced += 1
        body = m.group(2).encode().decode("unicode_escape", errors="replace")
        return f"/* decoded eval(lit) */\n{body}\n"

    def _repl_charcode(m: re.Match) -> str:
        nonlocal replaced
        nums_raw = m.group(1)
        try:
            codes = [int(x.strip()) for x in nums_raw.split(",") if x.strip()]
        except ValueError:
            return m.group(0)
        if not codes or any(c < 0 or c > 0x10FFFF for c in codes):
            return m.group(0)
        try:
            text = "".join(chr(c) for c in codes)
        except (ValueError, OverflowError):
            return m.group(0)
        printable_ratio = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t") / len(text)
        if printable_ratio < 0.85:
            return m.group(0)
        replaced += 1
        safe = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{safe}" /* <-- fromCharCode({len(codes)}) */'

    def _repl_buffer_from(m: re.Match) -> str:
        nonlocal replaced
        payload = m.group(2)
        enc = m.group(4)
        try:
            if enc == "base64":
                raw = base64.b64decode(payload.encode())
            else:
                raw = bytes.fromhex(payload)
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)
        printable_ratio = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t") / max(len(text), 1)
        if printable_ratio < 0.85:
            return m.group(0)
        replaced += 1
        safe = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{safe}" /* <-- Buffer.from({enc}) */'

    def _repl_hex_escape_str(m: re.Match) -> str:
        nonlocal replaced
        quote = m.group(1)
        escaped = m.group(2)
        try:
            bytes_list: List[int] = []
            i = 0
            while i < len(escaped):
                if escaped[i:i+2] == "\\x":
                    bytes_list.append(int(escaped[i+2:i+4], 16))
                    i += 4
                else:
                    return m.group(0)
            text = bytes(bytes_list).decode("utf-8", errors="replace")
        except Exception:
            return m.group(0)
        printable_ratio = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t") / max(len(text), 1)
        if printable_ratio < 0.85:
            return m.group(0)
        replaced += 1
        safe = text.replace("\\", "\\\\").replace(quote, f"\\{quote}").replace("\n", "\\n")
        return f'{quote}{safe}{quote} /* <-- hex */'

    new_src = EVAL_ATOB_RE.sub(_repl_atob_in_eval, source)
    new_src = FUNCTION_STR_RE.sub(_repl_fn, new_src)
    new_src = EVAL_LITERAL_RE.sub(_repl_eval_lit, new_src)
    new_src = FROM_CHARCODE_RE.sub(_repl_charcode, new_src)
    new_src = BUFFER_FROM_RE.sub(_repl_buffer_from, new_src)
    new_src = HEX_ESCAPE_STR_RE.sub(_repl_hex_escape_str, new_src)
    # 裸 atob 放最后：避免把前面的 eval(atob(...)) 二次折叠
    new_src = ATOB_BARE_RE.sub(_repl_atob_bare, new_src)

    # 多趟递归：有些样本层层嵌套（atob 内再 atob），跑 2 次足够
    for _ in range(2):
        prev = new_src
        new_src = ATOB_BARE_RE.sub(_repl_atob_bare, new_src)
        new_src = FROM_CHARCODE_RE.sub(_repl_charcode, new_src)
        if new_src == prev:
            break

    if replaced == 0:
        return None, 0
    return new_src, replaced


# ----------------------------------------------------------------------
# 路由表 + 产物写盘
# ----------------------------------------------------------------------

ROUTE_PY = {"b64_chain", "hex_chain", "zlib_chain", "pyarmor", "pyc_marshal", "mixed_heavy"}
ROUTE_JS = {"jsobf_stringarray", "webpack_bundle", "jsfuck", "aaencode", "eval_string", "mixed_heavy"}


def _write_deob(extract_dir: str, file_rel: str, new_source: str) -> str:
    """写回 deobf/<relpath>.deob.{py|js}，返回相对路径。"""
    stem, ext = os.path.splitext(file_rel)
    out_rel = os.path.join("deobf", f"{stem}.deob{ext}")
    out_abs = os.path.join(extract_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        f.write(new_source)
    return out_rel.replace("\\", "/")


def deobfuscate_file(
    extract_dir: str,
    file_rel: str,
    ecosystem: str,
    obf_class: str,
    original_source: str,
) -> DeobResult:
    """对单个文件按 obf_class 调用对应工具链。"""
    if obf_class == "none":
        return DeobResult(False, "skipped", None, "no_obfuscation")

    # --------  Python 路线  --------
    if ecosystem == "pypi":
        if obf_class in ("b64_chain", "hex_chain", "zlib_chain", "mixed_heavy"):
            new_src, n = deobfuscate_python_file(original_source)
            if new_src and n > 0 and _deob_quality_improved(original_source, new_src):
                out_rel = _write_deob(extract_dir, file_rel, new_src)
                return DeobResult(True, "ast_const_chain", out_rel)
            return DeobResult(False, "failed", None, "ast_const_chain_no_match_or_no_improvement")
        if obf_class in ("pyarmor", "pyc_marshal"):
            # 外部工具未集成 -> 失败
            return DeobResult(False, "failed", None, f"{obf_class}_tool_not_integrated")

    # --------  NPM 路线  --------
    if ecosystem == "npm":
        if obf_class in ("eval_string", "mixed_heavy"):
            new_src, n = deobfuscate_js_eval_string(original_source)
            if new_src and n > 0:
                out_rel = _write_deob(extract_dir, file_rel, new_src)
                return DeobResult(True, "js_eval_string_fold", out_rel)
            return DeobResult(False, "failed", None, "eval_string_no_match")
        if obf_class in ("jsobf_stringarray", "webpack_bundle", "jsfuck", "aaencode"):
            return DeobResult(False, "failed", None, f"{obf_class}_tool_not_integrated")

    return DeobResult(False, "failed", None, f"unroutable:{obf_class}")


def _deob_quality_improved(old: str, new: str) -> bool:
    """§4.5.3：entropy 降 >= 0.5 或单行最大长度降 >= 50%。"""
    try:
        old_h = shannon_entropy(old)
        new_h = shannon_entropy(new)
        old_m = max_line_length(old)
        new_m = max_line_length(new)
        if (old_h - new_h) >= 0.5:
            return True
        if old_m >= 100 and new_m <= old_m * 0.5:
            return True
        # 能解析 AST 且替换发生也视为成功
        ast.parse(new)
        return True
    except SyntaxError:
        return False
    except Exception:
        return True
