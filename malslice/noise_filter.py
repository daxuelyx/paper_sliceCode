"""§4.2 NoiseFilter：噪音文件剔除。"""
from __future__ import annotations

import os
from typing import List, Tuple


FORCE_KEEP_BASENAMES = {
    "package.json", "package-lock.json",
    "setup.py", "setup.cfg", "pyproject.toml", "MANIFEST.in",
    ".npmrc", ".pypirc",
}

WHITELIST_EXTS_NPM = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
WHITELIST_EXTS_PY = {".py", ".pyx", ".pyi"}

BLACKLIST_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".mp3", ".mp4", ".wav", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".md", ".rst", ".txt", ".csv", ".tsv",
    ".yaml", ".yml", ".lock", ".license",
    ".map",
}

BLACKLIST_DIR_SEGMENTS = {
    "node_modules", "test", "tests", "__tests__", "spec", "examples", "example",
    "docs", "doc", ".github", ".git", "dist-types",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
}

MAX_FILE_SIZE = 5 * 1024 * 1024


def _path_has_blacklisted_dir(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return any(seg in BLACKLIST_DIR_SEGMENTS for seg in parts[:-1])


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        return True
    if b"\x00" in head:
        return True
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def filter_files(extract_dir: str, ecosystem: str) -> Tuple[List[str], List[str]]:
    """返回 (keep_paths, dropped_paths)，均为相对 extract_dir 的路径。"""
    if ecosystem == "npm":
        whitelist_exts = WHITELIST_EXTS_NPM
    elif ecosystem == "pypi":
        whitelist_exts = WHITELIST_EXTS_PY
    else:
        whitelist_exts = WHITELIST_EXTS_NPM | WHITELIST_EXTS_PY

    keep: List[str] = []
    dropped: List[str] = []
    for root, _dirs, files in os.walk(extract_dir):
        for fn in files:
            abs_path = os.path.join(root, fn)
            rel = os.path.relpath(abs_path, extract_dir)

            basename = os.path.basename(rel)
            ext = os.path.splitext(basename)[1].lower()

            # 1. 强制保留清单文件（注意保留的是路径第一层附近，通常为根目录）
            if basename in FORCE_KEEP_BASENAMES:
                keep.append(rel)
                continue

            # 4. 黑名单目录（先判，优先级高于白名单扩展）
            if _path_has_blacklisted_dir(rel):
                dropped.append(rel)
                continue

            # 3. 黑名单扩展
            if ext in BLACKLIST_EXTS:
                dropped.append(rel)
                continue

            # 2. 白名单扩展
            if ext not in whitelist_exts:
                dropped.append(rel)
                continue

            # 6. 体积上限
            try:
                if os.path.getsize(abs_path) > MAX_FILE_SIZE:
                    dropped.append(rel)
                    continue
            except OSError:
                dropped.append(rel)
                continue

            # 5. 二进制硬判
            if _is_binary(abs_path):
                dropped.append(rel)
                continue

            keep.append(rel)

    return keep, dropped
