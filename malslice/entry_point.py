"""§4.3 EntryPointLocator：给文件打 entry_kind 标签。"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


# -----------------------------  NPM  -----------------------------

NPM_LIFECYCLE_SCRIPTS = {
    "preinstall", "install", "postinstall",
    "prepublish", "prepare", "postpublish",
}


def _normalize_rel(p: str) -> str:
    return p.lstrip("./").replace("\\", "/")


def _script_target_file(script: str) -> Optional[str]:
    """从 scripts 的值中粗略提取被 node 执行的文件名。"""
    if not script:
        return None
    tokens = script.split()
    for i, t in enumerate(tokens):
        if t in ("node", "npx", "ts-node"):
            if i + 1 < len(tokens):
                nxt = tokens[i + 1]
                # 过滤 `-e` 内联脚本情形
                if nxt.startswith("-"):
                    return None
                return _normalize_rel(nxt)
        if t.endswith(".js") or t.endswith(".cjs") or t.endswith(".mjs"):
            return _normalize_rel(t)
    return None


def locate_entries_npm(extract_dir: str, keep_files: List[str]) -> Dict[str, str]:
    """返回 {rel_path: entry_kind}。"""
    pkg_json = os.path.join(extract_dir, "package.json")
    labels: Dict[str, str] = {}

    lifecycle_targets: set = set()
    bin_targets: set = set()
    main_targets: set = set()

    if os.path.isfile(pkg_json):
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}

        scripts = meta.get("scripts") or {}
        if isinstance(scripts, dict):
            for k, v in scripts.items():
                if k in NPM_LIFECYCLE_SCRIPTS and isinstance(v, str):
                    t = _script_target_file(v)
                    if t:
                        lifecycle_targets.add(t)

        bin_field = meta.get("bin")
        if isinstance(bin_field, str):
            bin_targets.add(_normalize_rel(bin_field))
        elif isinstance(bin_field, dict):
            for v in bin_field.values():
                if isinstance(v, str):
                    bin_targets.add(_normalize_rel(v))

        for key in ("main", "module"):
            v = meta.get(key)
            if isinstance(v, str):
                main_targets.add(_normalize_rel(v))

        exports = meta.get("exports")
        if isinstance(exports, str):
            main_targets.add(_normalize_rel(exports))
        elif isinstance(exports, dict):
            for k, v in exports.items():
                if isinstance(v, str):
                    main_targets.add(_normalize_rel(v))
                elif isinstance(v, dict):
                    for vv in v.values():
                        if isinstance(vv, str):
                            main_targets.add(_normalize_rel(vv))

    def _match(rel: str, targets: set) -> bool:
        rel_n = _normalize_rel(rel)
        if rel_n in targets:
            return True
        # 有些 main 指向无扩展名的路径，尝试补 .js
        for t in targets:
            if t == rel_n or rel_n == t + ".js" or rel_n == t + "/index.js":
                return True
        return False

    for rel in keep_files:
        if not rel.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
            continue
        if _match(rel, lifecycle_targets):
            labels[rel] = "npm_lifecycle"
        elif _match(rel, bin_targets):
            labels[rel] = "npm_bin"
        elif _match(rel, main_targets):
            labels[rel] = "npm_main"
        else:
            labels[rel] = "npm_other"
    return labels


# -----------------------------  PyPI  -----------------------------

def locate_entries_pypi(extract_dir: str, keep_files: List[str]) -> Dict[str, str]:
    labels: Dict[str, str] = {}

    # 读取 pyproject.toml（可选）
    pep517_hooks: set = set()
    entry_modules: set = set()

    pyproject = os.path.join(extract_dir, "pyproject.toml")
    if tomllib is not None and os.path.isfile(pyproject):
        try:
            with open(pyproject, "rb") as f:
                meta = tomllib.load(f)
        except Exception:
            meta = {}

        build_sys = meta.get("build-system") or {}
        backend = build_sys.get("build-backend")
        if isinstance(backend, str) and backend:
            mod = backend.split(":", 1)[0].split(".")
            if mod:
                entry_modules.add(mod[-1])  # 记录模块名

        proj = meta.get("project") or {}
        scripts = proj.get("scripts") or {}
        for v in scripts.values():
            if isinstance(v, str):
                mod = v.split(":", 1)[0]
                if mod:
                    entry_modules.add(mod)
        tool = meta.get("tool") or {}
        hatch = (tool.get("hatch") or {}).get("build", {}).get("hooks") or {}
        if isinstance(hatch, dict):
            for k in hatch.keys():
                pep517_hooks.add(k)

    for rel in keep_files:
        rel_n = _normalize_rel(rel)
        basename = os.path.basename(rel_n)

        # Level 0
        if basename == "setup.py":
            labels[rel] = "py_setup"
            continue
        if basename in ("pyproject.toml",):
            labels[rel] = "py_pep517_hook"
            continue
        # Level 1
        if basename.endswith(".pth"):
            labels[rel] = "py_pth"
            continue
        if basename in ("sitecustomize.py", "usercustomize.py"):
            labels[rel] = "py_sitecustomize"
            continue
        # Level 2
        if basename == "__init__.py":
            labels[rel] = "py_init"
            continue
        # Level 3
        if basename == "conftest.py":
            labels[rel] = "py_conftest"
            continue
        # 尝试按 entry_points 匹配
        # 若文件路径包含某个 entry_modules 的文件名对应，则标 py_entry_point
        stem = os.path.splitext(basename)[0]
        if stem in entry_modules:
            labels[rel] = "py_entry_point"
            continue

        labels[rel] = "py_other"

    return labels


def locate_entries(extract_dir: str, keep_files: List[str], ecosystem: str) -> Dict[str, str]:
    if ecosystem == "npm":
        return locate_entries_npm(extract_dir, keep_files)
    if ecosystem == "pypi":
        return locate_entries_pypi(extract_dir, keep_files)
    return {rel: "unknown" for rel in keep_files}


ENTRY_LEVEL = {
    # NPM
    "npm_lifecycle": 0,
    "npm_bin": 1,
    "npm_main": 2,
    "npm_top_level": 3,
    "npm_other": 4,
    # PyPI
    "py_setup": 0,
    "py_pep517_hook": 0,
    "py_pth": 1,
    "py_sitecustomize": 1,
    "py_init": 2,
    "py_entry_point": 2,
    "py_conftest": 3,
    "py_other": 4,
}
