"""通用工具：熵、语言识别、文本读取等。"""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Optional, Tuple


JS_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
PY_EXTS = {".py", ".pyx", ".pyi"}


def detect_language(path: str) -> Optional[str]:
    ext = os.path.splitext(path)[1].lower()
    if ext in JS_EXTS:
        return "js"
    if ext in PY_EXTS:
        return "py"
    return None


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def max_line_length(text: str) -> int:
    if not text:
        return 0
    return max((len(line) for line in text.splitlines()), default=0)


def avg_identifier_length(text: str) -> float:
    ids = re.findall(r"[A-Za-z_][A-Za-z_0-9]*", text)
    if not ids:
        return 999.0
    return sum(len(x) for x in ids) / len(ids)


def safe_read_text(path: str, limit_bytes: int = 5 * 1024 * 1024) -> Optional[str]:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > limit_bytes:
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
        if b"\x00" in head:
            return None
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, OSError):
        return None


def count_non_empty_lines(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.strip())


def line_window(text: str, center_line: int, half: int = 30) -> Tuple[str, Tuple[int, int]]:
    """以 center_line（1-indexed）为中心返回上下 half 行窗口，以及窗口的 (start,end)。"""
    lines = text.splitlines()
    start = max(1, center_line - half)
    end = min(len(lines), center_line + half)
    if start > end:
        return "", (1, 1)
    return "\n".join(lines[start - 1:end]), (start, end)
