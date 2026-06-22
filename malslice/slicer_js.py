"""§4.7 JavaScript AST 切片引擎（基于 esprima Python 实现）。

注意：esprima 只支持到 ES2017，TS/JSX/装饰器等不支持。
遇到解析失败时，回退到 regex/行窗口启发式切片，保证不漏切。
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple, Any

try:
    import esprima  # type: ignore
    HAS_ESPRIMA = True
except ImportError:  # pragma: no cover
    HAS_ESPRIMA = False

from .ir import FunctionSlice, compute_slice_id
from .sink_registry import (
    NPM_SENSITIVE_MODULES,
    NPM_REFLECTION_APIS,
)
from .utils import line_window, count_non_empty_lines


# ----------------------------------------------------------------------
# AST 节点辅助
# ----------------------------------------------------------------------

def _loc_range(node) -> Tuple[int, int]:
    loc = getattr(node, "loc", None)
    if not loc:
        return (1, 1)
    return (loc.start.line, loc.end.line)


def _walk(node, parents: Optional[List] = None):
    """深度遍历 AST，每次 yield (node, parents)。"""
    if parents is None:
        parents = []
    yield node, parents
    new_parents = parents + [node]
    for attr in getattr(node, "_keys", []) or dir(node):
        if attr.startswith("_") or attr in ("type", "loc", "range"):
            continue
        try:
            val = getattr(node, attr)
        except Exception:
            continue
        if isinstance(val, list):
            for item in val:
                if _is_ast_node(item):
                    yield from _walk(item, new_parents)
        elif _is_ast_node(val):
            yield from _walk(val, new_parents)


def _is_ast_node(x) -> bool:
    return hasattr(x, "type") and hasattr(x, "loc")


# ----------------------------------------------------------------------
# 导入 / 别名表
# ----------------------------------------------------------------------

def _collect_alias_map_and_imports(tree, source: str) -> Tuple[Dict[str, str], List[str]]:
    """返回 (alias_map, imports)。

    别名表：局部名 -> 规范模块（如 'child_process' 或 'child_process.exec'）。
    - const cp = require('child_process')         -> {'cp': 'child_process'}
    - const { exec } = require('child_process')   -> {'exec': 'child_process.exec'}
    - const { exec: e } = require('child_process')-> {'e':    'child_process.exec'}
    - import cp from 'child_process'              -> {'cp': 'child_process'}
    - import { exec } from 'child_process'        -> {'exec': 'child_process.exec'}
    """
    alias_map: Dict[str, str] = {}
    imports: List[str] = []
    source_lines = source.splitlines()

    for node, _parents in _walk(tree):
        t = getattr(node, "type", None)

        # ES Module imports
        if t == "ImportDeclaration":
            src_val = getattr(getattr(node, "source", None), "value", None)
            if isinstance(src_val, str):
                for spec in getattr(node, "specifiers", []) or []:
                    st = getattr(spec, "type", None)
                    if st == "ImportDefaultSpecifier":
                        local = getattr(getattr(spec, "local", None), "name", None)
                        if local:
                            alias_map[local] = src_val
                    elif st == "ImportSpecifier":
                        imported = getattr(getattr(spec, "imported", None), "name", None)
                        local = getattr(getattr(spec, "local", None), "name", None)
                        if local and imported:
                            alias_map[local] = f"{src_val}.{imported}"
                    elif st == "ImportNamespaceSpecifier":
                        local = getattr(getattr(spec, "local", None), "name", None)
                        if local:
                            alias_map[local] = src_val
            start, end = _loc_range(node)
            if 1 <= start <= len(source_lines):
                imports.append("\n".join(source_lines[start - 1: min(end, len(source_lines))]))
            continue

        # const x = require('y'), const {a,b} = require('y'), const x = require('y').z
        if t == "VariableDeclaration":
            for decl in getattr(node, "declarations", []) or []:
                init = getattr(decl, "init", None)
                if not init:
                    continue
                mod = _extract_require_module(init)
                if mod is None:
                    continue
                id_node = getattr(decl, "id", None)
                # 记录 imports 行
                start, end = _loc_range(node)
                if 1 <= start <= len(source_lines):
                    imports.append("\n".join(source_lines[start - 1: min(end, len(source_lines))]))

                if getattr(id_node, "type", None) == "Identifier":
                    local = getattr(id_node, "name", None)
                    # require('x').y 情形：把 mod 写成 'x.y'
                    if local:
                        alias_map[local] = mod
                elif getattr(id_node, "type", None) == "ObjectPattern":
                    for prop in getattr(id_node, "properties", []) or []:
                        if getattr(prop, "type", None) != "Property":
                            continue
                        key = getattr(prop, "key", None)
                        value = getattr(prop, "value", None)
                        key_name = getattr(key, "name", None) or getattr(key, "value", None)
                        if getattr(value, "type", None) == "Identifier":
                            local = getattr(value, "name", None)
                            if local and key_name:
                                alias_map[local] = f"{mod}.{key_name}"

    # 去重保序
    seen = set()
    uniq_imports: List[str] = []
    for line in imports:
        if line not in seen:
            seen.add(line)
            uniq_imports.append(line)
    return alias_map, uniq_imports


def _extract_require_module(init_node) -> Optional[str]:
    """处理 require('x'), require('x').y, require('x')[Y] 折叠。返回 'x' 或 'x.y' 或 None。"""
    t = getattr(init_node, "type", None)
    if t == "CallExpression":
        callee = getattr(init_node, "callee", None)
        if getattr(callee, "type", None) == "Identifier" and getattr(callee, "name", None) == "require":
            args = getattr(init_node, "arguments", []) or []
            if args and getattr(args[0], "type", None) == "Literal":
                val = getattr(args[0], "value", None)
                if isinstance(val, str):
                    return val
    if t == "MemberExpression":
        obj = getattr(init_node, "object", None)
        prop = getattr(init_node, "property", None)
        mod = _extract_require_module(obj)
        if mod is None:
            return None
        if getattr(init_node, "computed", False):
            # require('x')[var]  -> 无法折叠
            return mod
        prop_name = getattr(prop, "name", None)
        if prop_name:
            return f"{mod}.{prop_name}"
    return None


# ----------------------------------------------------------------------
# 规范名解析
# ----------------------------------------------------------------------

def _member_chain_names(node) -> Optional[List[str]]:
    """a.b.c -> ['a','b','c']；若包含 computed 属性或非 Identifier，返回 None。"""
    parts: List[str] = []
    cur = node
    while getattr(cur, "type", None) == "MemberExpression":
        if getattr(cur, "computed", False):
            return None
        prop = getattr(cur, "property", None)
        name = getattr(prop, "name", None)
        if not name:
            return None
        parts.append(name)
        cur = getattr(cur, "object", None)
    if getattr(cur, "type", None) == "Identifier":
        parts.append(getattr(cur, "name", None) or "")
        return list(reversed(parts))
    return None


def resolve_js_qualified_name(node, alias_map: Dict[str, str]) -> Optional[str]:
    t = getattr(node, "type", None)
    if t == "Identifier":
        name = getattr(node, "name", None)
        if name:
            return alias_map.get(name, name)
        return None
    if t == "MemberExpression":
        chain = _member_chain_names(node)
        if not chain:
            return None
        head = chain[0]
        mapped = alias_map.get(head, head)
        return mapped + "." + ".".join(chain[1:])
    if t == "CallExpression":
        callee = getattr(node, "callee", None)
        # require('x') 专门处理
        if getattr(callee, "type", None) == "Identifier" and getattr(callee, "name", None) == "require":
            args = getattr(node, "arguments", []) or []
            if args and getattr(args[0], "type", None) == "Literal":
                val = getattr(args[0], "value", None)
                if isinstance(val, str):
                    return f"require('{val}')"
        return resolve_js_qualified_name(callee, alias_map)
    if t == "NewExpression":
        callee = getattr(node, "callee", None)
        name = resolve_js_qualified_name(callee, alias_map) or ""
        return f"new {name}"
    return None


def _is_js_reflection_call(call, alias_map: Dict[str, str]) -> Optional[str]:
    qname = resolve_js_qualified_name(call, alias_map) or ""
    for api in NPM_REFLECTION_APIS:
        if qname == api or qname.endswith("." + api):
            return api
    # new Function(...)
    if getattr(call, "type", None) == "NewExpression":
        callee = getattr(call, "callee", None)
        if getattr(callee, "type", None) == "Identifier" and getattr(callee, "name", None) == "Function":
            return "new Function"
    # Function('code') (不加 new)
    if getattr(call, "type", None) == "CallExpression":
        callee = getattr(call, "callee", None)
        if getattr(callee, "type", None) == "Identifier" and getattr(callee, "name", None) == "Function":
            return "Function"
    return None


def _is_js_dynamic_member_call(call, alias_map: Dict[str, str]) -> Optional[str]:
    """obj[var](...) / require(var).exec(...) 等；返回接收者敏感模块规范名，否则 None。"""
    if getattr(call, "type", None) not in ("CallExpression", "NewExpression"):
        return None
    callee = getattr(call, "callee", None)
    if getattr(callee, "type", None) != "MemberExpression":
        return None
    if not getattr(callee, "computed", False):
        return None
    # property 是字面量字符串 -> 在 §4.6.x 中归为 static/computed_literal，不算 dynamic
    prop = getattr(callee, "property", None)
    if getattr(prop, "type", None) == "Literal" and isinstance(getattr(prop, "value", None), str):
        return None
    # 接收者规范名
    obj = getattr(callee, "object", None)
    qname = resolve_js_qualified_name(obj, alias_map) or ""
    head = qname.split(".")[0]
    if head in NPM_SENSITIVE_MODULES:
        return head
    # require(var)(...) / require(var).x(...) 也算 dynamic_require
    if qname.startswith("require("):
        return "require"
    return None


# ----------------------------------------------------------------------
# 函数祖先
# ----------------------------------------------------------------------

FUNC_TYPES = {
    "FunctionDeclaration",
    "FunctionExpression",
    "ArrowFunctionExpression",
}


def _nearest_enclosing_fn_js(parents: List) -> Optional[Any]:
    for p in reversed(parents):
        t = getattr(p, "type", None)
        if t in FUNC_TYPES:
            return p
        if t == "ClassDeclaration" or t == "ClassExpression":
            return p
    return None


def _fn_name_js(fn) -> str:
    t = getattr(fn, "type", None)
    if t == "FunctionDeclaration":
        nm = getattr(getattr(fn, "id", None), "name", None)
        return nm or "__anonymous__"
    if t == "FunctionExpression":
        nm = getattr(getattr(fn, "id", None), "name", None)
        return nm or "__anonymous__"
    if t == "ArrowFunctionExpression":
        return "__arrow__"
    if t in ("ClassDeclaration", "ClassExpression"):
        nm = getattr(getattr(fn, "id", None), "name", None)
        return f"__classbody__{nm or 'Anonymous'}"
    return "__anonymous__"


# ----------------------------------------------------------------------
# 切片主逻辑
# ----------------------------------------------------------------------

def _collect_npm_sink_hits(
    tree,
    alias_map: Dict[str, str],
    sinks: Set[str],
):
    """遍历 AST，返回 [(node, sink_name, sink_kind, parents)]。"""
    hits: List[Tuple[Any, str, str, List]] = []
    for node, parents in _walk(tree):
        t = getattr(node, "type", None)
        if t not in ("CallExpression", "NewExpression"):
            continue

        qname = resolve_js_qualified_name(node, alias_map)
        static_hit = False
        if qname:
            # 精确规范名
            if qname in sinks:
                hits.append((node, qname, "static", list(parents)))
                static_hit = True
            else:
                # 末段匹配（处理别名把完整模块路径包住的情形）
                for s in sinks:
                    if "." in s and qname.endswith("." + s):
                        hits.append((node, s, "static", list(parents)))
                        static_hit = True
                        break
        if static_hit:
            continue

        # 反射
        refl = _is_js_reflection_call(node, alias_map)
        if refl:
            hits.append((node, refl, "reflection", list(parents)))
            continue

        # 动态
        dyn_base = _is_js_dynamic_member_call(node, alias_map)
        if dyn_base:
            hits.append((node, f"__dyn_{dyn_base}__", "dynamic", list(parents)))
            continue

    return hits


def _resolve_local_callees_js(fn, tree, source_lines: List[str]) -> List[str]:
    """JS 的一跳本地 callee：同文件顶层 function 声明 + const f = function/arrow。"""
    # 收集顶层可调用名
    local_funcs: Dict[str, Any] = {}
    for top in getattr(tree, "body", []) or []:
        t = getattr(top, "type", None)
        if t == "FunctionDeclaration":
            nm = getattr(getattr(top, "id", None), "name", None)
            if nm:
                local_funcs[nm] = top
        elif t == "VariableDeclaration":
            for decl in getattr(top, "declarations", []) or []:
                init = getattr(decl, "init", None)
                if getattr(init, "type", None) in ("FunctionExpression", "ArrowFunctionExpression"):
                    nm = getattr(getattr(decl, "id", None), "name", None)
                    if nm:
                        local_funcs[nm] = init
    # 扫描 fn 内的 Identifier 调用
    called: Set[str] = set()
    for n, _p in _walk(fn):
        if getattr(n, "type", None) == "CallExpression":
            callee = getattr(n, "callee", None)
            if getattr(callee, "type", None) == "Identifier":
                nm = getattr(callee, "name", None)
                if nm:
                    called.add(nm)
    bodies: List[str] = []
    for nm in called:
        if nm in local_funcs and local_funcs[nm] is not fn:
            start, end = _loc_range(local_funcs[nm])
            if 1 <= start <= len(source_lines):
                bodies.append("\n".join(source_lines[start - 1: min(end, len(source_lines))]))
    return bodies


def slice_js_file(
    source: str,
    file_rel: str,
    package: str,
    entry_kind: str,
    sinks: Set[str],
    reslice_version: int = 0,
    parent_slices_by_key: Optional[Dict[Tuple[str, str, str], str]] = None,
    was_obfuscated: bool = False,
    deob_tool: Optional[str] = None,
) -> List[FunctionSlice]:
    if not HAS_ESPRIMA:
        return _fallback_regex_slice(
            source, file_rel, package, entry_kind, sinks,
            reslice_version, was_obfuscated, deob_tool,
        )
    # 先尝试 module，再 script
    tree = None
    for src_type in ("module", "script"):
        try:
            tree = esprima.parseScript(
                source, options={"loc": True, "range": False, "tolerant": True},
            ) if src_type == "script" else esprima.parseModule(
                source, options={"loc": True, "range": False, "tolerant": True},
            )
            break
        except Exception:
            tree = None
    if tree is None:
        return _fallback_regex_slice(
            source, file_rel, package, entry_kind, sinks,
            reslice_version, was_obfuscated, deob_tool,
        )

    source_lines = source.splitlines()
    alias_map, imports = _collect_alias_map_and_imports(tree, source)
    hits = _collect_npm_sink_hits(tree, alias_map, sinks)

    by_func: Dict[Tuple[str, int, int, str], Dict] = {}
    for hit_node, sink_name, sink_kind, parents in hits:
        fn = _nearest_enclosing_fn_js(parents)
        if fn is None:
            # 顶层命中
            center = _loc_range(hit_node)[0]
            src, (start, end) = line_window(source, center, half=30)
            func_name = "__toplevel__"
            fn_node_for_callees = None
        else:
            start, end = _loc_range(fn)
            if 1 <= start <= len(source_lines):
                src = "\n".join(source_lines[start - 1: min(end, len(source_lines))])
            else:
                src = ""
            func_name = _fn_name_js(fn)
            fn_node_for_callees = fn

        key = (file_rel, func_name, start, end, sink_kind)
        entry = by_func.setdefault(key, {
            "sinks": set(),
            "fn_node": fn_node_for_callees,
            "func_name": func_name,
            "src": src,
            "range": (start, end),
        })
        entry["sinks"].add(sink_name)

    slices: List[FunctionSlice] = []
    for key, data in by_func.items():
        file_rel_k, func_name, start, end, sink_kind = key
        src = data["src"]
        hint: Dict = {}
        if count_non_empty_lines(src) < 3:
            center = (start + end) // 2 if start and end else 1
            src, (start2, end2) = line_window(source, center, half=60)
            hint["short_body"] = True
            start, end = start2, end2

        callees_inline: List[str] = []
        if data["fn_node"] is not None:
            callees_inline = _resolve_local_callees_js(data["fn_node"], tree, source_lines)

        sinks_list = sorted(data["sinks"])

        parent_id = None
        if parent_slices_by_key is not None:
            pass1_file = file_rel
            if pass1_file.startswith("deobf/") and pass1_file.endswith(".deob.js"):
                pass1_file = pass1_file[len("deobf/"):-len(".deob.js")] + ".js"
            sink_joined = "|".join(sinks_list)
            parent_id = parent_slices_by_key.get((pass1_file, func_name, sink_joined))

        sid = compute_slice_id(package, file_rel, func_name, sinks_list, reslice_version)

        if sink_kind == "dynamic":
            hint["dynamic_probe"] = True

        fs = FunctionSlice(
            slice_id=sid,
            package=package,
            ecosystem="npm",
            file=file_rel,
            entry_kind=entry_kind,
            sink=sinks_list,
            sink_kind=sink_kind,
            func_name=func_name,
            func_range=(start, end),
            source_code=src,
            callees_inline=callees_inline,
            imports=imports,
            reslice_version=reslice_version,
            parent_slice_id=parent_id,
            was_obfuscated=was_obfuscated,
            deob_tool=deob_tool,
            confidence_hint=hint,
        )
        slices.append(fs)

    return slices


# ----------------------------------------------------------------------
# 解析失败时的行级兜底：仅基于正则命中 Sink 名 + 函数行窗口
# ----------------------------------------------------------------------

_JS_FN_RE = re.compile(
    r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", re.MULTILINE
)


def _fallback_regex_slice(
    source: str,
    file_rel: str,
    package: str,
    entry_kind: str,
    sinks: Set[str],
    reslice_version: int,
    was_obfuscated: bool,
    deob_tool: Optional[str],
) -> List[FunctionSlice]:
    """AST 解析失败时用正则做最小兜底：找 sink 字面子串 + ±30 行窗口。"""
    slices: List[FunctionSlice] = []
    lines = source.splitlines()
    # 只挑选 sinks 中"关键名"（避免过度误杀；取 . 后末段）
    key_tokens: Set[str] = set()
    for s in sinks:
        tail = s.split(".")[-1]
        if tail and len(tail) >= 3 and tail.isidentifier():
            key_tokens.add(tail)
    key_tokens.update({"eval", "Function", "exec", "require"})

    hit_lines: Dict[int, Set[str]] = {}
    for i, line in enumerate(lines, start=1):
        for tok in key_tokens:
            # 简单命中：词边界
            if re.search(rf"\b{re.escape(tok)}\b\s*\(", line):
                hit_lines.setdefault(i, set()).add(tok)

    seen_ranges: Set[Tuple[int, int]] = set()
    for i, sink_tokens in hit_lines.items():
        src, (start, end) = line_window(source, i, half=30)
        if (start, end) in seen_ranges:
            continue
        seen_ranges.add((start, end))

        func_name = "__toplevel__"
        # 尝试找最近的 function 声明
        for m in _JS_FN_RE.finditer(source):
            line_no = source[: m.start()].count("\n") + 1
            if line_no <= i:
                func_name = m.group(1)
            else:
                break

        sinks_list = sorted(sink_tokens)
        sid = compute_slice_id(package, file_rel, func_name, sinks_list, reslice_version)
        hint = {"fallback_regex": True}
        if count_non_empty_lines(src) < 3:
            hint["short_body"] = True

        fs = FunctionSlice(
            slice_id=sid,
            package=package,
            ecosystem="npm",
            file=file_rel,
            entry_kind=entry_kind,
            sink=sinks_list,
            sink_kind="static",
            func_name=func_name,
            func_range=(start, end),
            source_code=src,
            callees_inline=[],
            imports=[],
            reslice_version=reslice_version,
            parent_slice_id=None,
            was_obfuscated=was_obfuscated,
            deob_tool=deob_tool,
            confidence_hint=hint,
        )
        slices.append(fs)
    return slices
