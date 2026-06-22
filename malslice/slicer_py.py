"""§4.7 Python AST 函数级切片引擎。"""
from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

from .ir import FunctionSlice, compute_slice_id
from .sink_registry import (
    PY_SENSITIVE_MODULES,
    PY_REFLECTION_APIS,
    load_py_sinks,
)
from .utils import line_window, count_non_empty_lines


PY_SINKS = load_py_sinks()


# ----------------------------------------------------------------------
# 别名表：解析 import 语句把局部名映射回规范名
# ----------------------------------------------------------------------

def collect_alias_map(tree: ast.AST) -> Dict[str, str]:
    """{local_name: canonical_name}。

    - `import os`                       -> {'os': 'os'}
    - `import os.path as op`            -> {'op': 'os.path'}
    - `from subprocess import Popen`    -> {'Popen': 'subprocess.Popen'}
    - `from subprocess import Popen as P` -> {'P': 'subprocess.Popen'}
    """
    alias_map: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                canonical = a.name
                local = a.asname or a.name.split(".")[0]
                alias_map[local] = canonical
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            base = node.module
            for a in node.names:
                local = a.asname or a.name
                alias_map[local] = f"{base}.{a.name}"
    return alias_map


def collect_import_lines(tree: ast.AST, source_lines: List[str]) -> List[str]:
    out: List[str] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            # 行号 1-indexed
            start = node.lineno - 1
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            out.append("\n".join(source_lines[start:end]))
    return out


# ----------------------------------------------------------------------
# 规范名解析
# ----------------------------------------------------------------------

def _attr_chain(node: ast.AST) -> Optional[List[str]]:
    """把 a.b.c 还原成 ['a', 'b', 'c']。非此形式返回 None。"""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return list(reversed(parts))
    return None


def resolve_qualified_name(call_or_attr: ast.AST, alias_map: Dict[str, str]) -> Optional[str]:
    """给定 Call 的 func 或 Attribute 节点，解析为规范名（如 'subprocess.Popen'）。"""
    if isinstance(call_or_attr, ast.Call):
        target = call_or_attr.func
    else:
        target = call_or_attr

    if isinstance(target, ast.Name):
        local = target.id
        return alias_map.get(local, local)

    parts = _attr_chain(target)
    if not parts:
        return None
    head = parts[0]
    mapped = alias_map.get(head, head)
    return mapped + "." + ".".join(parts[1:])


def is_reflection_call(call: ast.Call, alias_map: Dict[str, str]) -> Optional[str]:
    qname = resolve_qualified_name(call, alias_map)
    if qname and qname in PY_REFLECTION_APIS:
        return qname
    # 顶层裸名（builtins）
    if isinstance(call.func, ast.Name) and call.func.id in PY_REFLECTION_APIS:
        return call.func.id
    return None


def is_dynamic_member_call(call: ast.Call, alias_map: Dict[str, str]) -> Optional[str]:
    """接收者是敏感模块，属性名为变量或表达式时命中。

    命中情形:
      - child_process[var](...)            # ast.Subscript
      - getattr(os, name)(...)             # outer call 的 func 是 getattr(...)
      - subprocess.__dict__[k](...)        # chain 含 __dict__
    返回敏感模块规范名；否则 None。
    """
    func = call.func
    # 1) obj[var](...) - Subscript
    if isinstance(func, ast.Subscript):
        base = func.value
        # 如果属性名本身是 Constant 字面量，不归为 dynamic（静态可识别）
        slice_val = func.slice
        if isinstance(slice_val, ast.Constant):
            return None
        # base 可能是 Name 或 Attribute
        qname = resolve_qualified_name(base, alias_map) or ""
        root = qname.split(".")[0]
        if root in PY_SENSITIVE_MODULES:
            return root

    # 2) getattr(mod, var)(...)
    if isinstance(func, ast.Call):
        inner = func
        inner_q = resolve_qualified_name(inner, alias_map)
        if inner_q in ("getattr",) and inner.args:
            mod_arg = inner.args[0]
            qname = resolve_qualified_name(mod_arg, alias_map) or ""
            root = qname.split(".")[0]
            if root in PY_SENSITIVE_MODULES:
                # 第二参非字面量才算 dynamic
                if len(inner.args) >= 2 and not isinstance(inner.args[1], ast.Constant):
                    return root

    return None


# ----------------------------------------------------------------------
# 切片主逻辑
# ----------------------------------------------------------------------

FunctionNode = (ast.FunctionDef, ast.AsyncFunctionDef)


def _nearest_enclosing_function(path: List[ast.AST]) -> Optional[ast.AST]:
    """path 是从根到当前节点的父链；返回最近的函数节点（不含 lambda，lambda 归并到外层）。"""
    for node in reversed(path):
        if isinstance(node, FunctionNode):
            return node
        if isinstance(node, ast.ClassDef):
            # 进入类体但还未进入方法 -> 返回类体，后续合成 __classbody__
            return node
    return None


def _collect_sink_hits(tree: ast.AST, alias_map: Dict[str, str]) -> List[Tuple[ast.AST, str, str, List[ast.AST]]]:
    """返回 [(node, sink_name, sink_kind, path_to_node)] 列表。path_to_node 是父链。"""
    hits: List[Tuple[ast.AST, str, str, List[ast.AST]]] = []

    def visit(node: ast.AST, path: List[ast.AST]) -> None:
        # 命中判断
        if isinstance(node, ast.Call):
            qname = resolve_qualified_name(node, alias_map)
            static_hit = False
            if qname:
                # 完全匹配
                if qname in PY_SINKS:
                    hits.append((node, qname, "static", list(path)))
                    static_hit = True
                else:
                    # 部分前缀匹配（如 urllib.request.urlopen 的缩写）
                    # 不做太激进的匹配，只做完整规范名匹配以减少 FP
                    pass
            if not static_hit:
                refl = is_reflection_call(node, alias_map)
                if refl:
                    hits.append((node, refl, "reflection", list(path)))
                else:
                    dyn_base = is_dynamic_member_call(node, alias_map)
                    if dyn_base:
                        hits.append((node, f"__dyn_{dyn_base}__", "dynamic", list(path)))

        elif isinstance(node, ast.Attribute):
            # 成员访问，如 os.environ['TOKEN']（实际 Subscript 包 Attribute）；这里只检查 os.environ 命中
            qname = resolve_qualified_name(node, alias_map)
            if qname and qname in PY_SINKS:
                # 避免和 Call 重复：如果父链末尾是 Call 且 Call.func 就是自身，跳过
                parent = path[-1] if path else None
                if isinstance(parent, ast.Call) and parent.func is node:
                    pass
                else:
                    hits.append((node, qname, "static", list(path)))

        # 递归
        new_path = path + [node]
        for child in ast.iter_child_nodes(node):
            visit(child, new_path)

    visit(tree, [])
    return hits


def _unparse(node: ast.AST, source_lines: List[str]) -> Tuple[str, Tuple[int, int]]:
    """优先按源码行号截取以保持可读性；失败时退回 ast.unparse。"""
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    if start and end and 1 <= start <= len(source_lines):
        end = min(end, len(source_lines))
        src = "\n".join(source_lines[start - 1:end])
        return src, (start, end)
    try:
        src = ast.unparse(node)
        return src, (getattr(node, "lineno", 1), getattr(node, "end_lineno", 1))
    except Exception:
        return "", (1, 1)


def _resolve_local_callees(fn: ast.AST, module_tree: ast.AST,
                           source_lines: List[str]) -> List[str]:
    """一跳本地 callee 内联：fn 内直接调用且在同文件定义的函数体。"""
    # 收集模块级所有 def / async def 的 name -> node
    local_funcs: Dict[str, ast.AST] = {}
    for top in ast.iter_child_nodes(module_tree):
        if isinstance(top, FunctionNode):
            local_funcs[top.name] = top
        elif isinstance(top, ast.ClassDef):
            for item in ast.iter_child_nodes(top):
                if isinstance(item, FunctionNode):
                    # 类方法不参与"一跳"展开，但保留 name 备用
                    pass

    called_names: Set[str] = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Name):
                called_names.add(sub.func.id)

    inline_bodies: List[str] = []
    for name in called_names:
        if name in local_funcs and local_funcs[name] is not fn:
            src, _ = _unparse(local_funcs[name], source_lines)
            if src:
                inline_bodies.append(src)
    return inline_bodies


def slice_python_file(
    source: str,
    file_rel: str,
    package: str,
    entry_kind: str,
    reslice_version: int = 0,
    parent_slices_by_key: Optional[Dict[Tuple[str, str, str], str]] = None,
    was_obfuscated: bool = False,
    deob_tool: Optional[str] = None,
) -> List[FunctionSlice]:
    """对单个 Python 文件产出 FunctionSlice 列表。

    parent_slices_by_key: pass2 使用，{(file, func_name, sink_joined): pass1_slice_id}
        用于写 parent_slice_id。
    """
    try:
        tree = ast.parse(source, filename=file_rel)
    except SyntaxError:
        return []

    source_lines = source.splitlines()
    alias_map = collect_alias_map(tree)
    imports = collect_import_lines(tree, source_lines)

    hits = _collect_sink_hits(tree, alias_map)

    # 按 (func_name, hit_line) 聚类同函数多 Sink
    by_func: Dict[Tuple[str, int, int, str], Dict] = {}
    # key: (func_name, start, end, sink_kind)，value: {'sinks': set, 'node': fn_node, ...}

    for hit_node, sink_name, sink_kind, path in hits:
        fn = _nearest_enclosing_function(path)
        if fn is None:
            # 顶层命中 -> 合成 __toplevel__，带 ±30 行窗口
            center = getattr(hit_node, "lineno", 1)
            src, (start, end) = line_window(source, center, half=30)
            func_name = "__toplevel__"
        elif isinstance(fn, ast.ClassDef):
            # 类体直接语句
            src, (start, end) = _unparse(fn, source_lines)
            func_name = f"__classbody__{fn.name}"
        else:
            src, (start, end) = _unparse(fn, source_lines)
            func_name = getattr(fn, "name", "__anonymous__") or "__anonymous__"

        key = (file_rel, func_name, start, end, sink_kind)
        entry = by_func.setdefault(key, {
            "sinks": set(),
            "fn_node": fn if isinstance(fn, FunctionNode) else None,
            "func_name": func_name,
            "src": src,
            "range": (start, end),
        })
        entry["sinks"].add(sink_name)

    # 构建切片
    slices: List[FunctionSlice] = []
    for key, data in by_func.items():
        file_rel_k, func_name, start, end, sink_kind = key
        src = data["src"]
        # §7 防切空：source_code 短于 3 非空行 -> 扩窗
        hint: Dict = {}
        if count_non_empty_lines(src) < 3:
            center = (start + end) // 2 if start and end else 1
            src, (start2, end2) = line_window(source, center, half=60)
            hint["short_body"] = True
            start, end = start2, end2

        callees_inline: List[str] = []
        if data["fn_node"] is not None:
            callees_inline = _resolve_local_callees(data["fn_node"], tree, source_lines)

        sinks_list = sorted(data["sinks"])

        parent_id = None
        if parent_slices_by_key is not None:
            pass1_file = file_rel
            # pass2 的 file 带 .deob 后缀，尝试去掉
            if pass1_file.startswith("deobf/") and pass1_file.endswith(".deob.py"):
                pass1_file = pass1_file[len("deobf/"):-len(".deob.py")] + ".py"
            sink_joined = "|".join(sinks_list)
            parent_id = parent_slices_by_key.get((pass1_file, func_name, sink_joined))

        sid = compute_slice_id(package, file_rel, func_name, sinks_list, reslice_version)

        # dynamic 探针 FP 缓释的 hint 提示
        if sink_kind == "dynamic":
            hint["dynamic_probe"] = True

        fs = FunctionSlice(
            slice_id=sid,
            package=package,
            ecosystem="pypi",
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
