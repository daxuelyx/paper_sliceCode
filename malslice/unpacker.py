"""§4.1 Unpacker：tar.gz / zip(wheel) 解包 + 规范化。

改进 ①（v2）：很多 PyPI 恶意包以 `*.tar.gz` 文件名伪装，但实际是 wheel
（zip 容器）。早期实现只调 `tarfile.open()`，遇到 wheel 直接 extract_failed
→ 0 文件 → 0 切片 → benign 兜底，导致典型 typosquat 漏检。

现在入口先嗅探 magic：
  - 头 4 字节是 `PK\x03\x04` (zip local file header) 或 `PK\x05\x06`
    (空 zip eocd) → 走 `zipfile.ZipFile`
  - 否则走原来的 `tarfile.open("r:*")`
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import zipfile
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class UnpackResult:
    package: str                   # "name@version"
    ecosystem: str
    tarball: str
    extract_dir: str
    file_count: int = 0
    byte_count: int = 0
    raw_sha1: str = ""
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


def _sha1_of_file(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _strip_leading_pkg_dir(extract_dir: str) -> None:
    """NPM tarball 顶层是 package/ 目录，内容需上提一层。"""
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    if len(entries) != 1:
        return
    only = os.path.join(extract_dir, entries[0])
    if not os.path.isdir(only):
        return
    if entries[0] not in ("package",):
        # 有些 NPM 包顶层也可能是包名目录，只在命中 "package/" 时上提
        return
    for item in os.listdir(only):
        src = os.path.join(only, item)
        dst = os.path.join(extract_dir, item)
        if os.path.exists(dst):
            dst = dst + "__nested"
        shutil.move(src, dst)
    shutil.rmtree(only, ignore_errors=True)


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    """规避 path traversal，类似 Python 3.12 的 data filter。"""
    dest_abs = os.path.abspath(dest)
    for member in tar.getmembers():
        # 丢弃设备文件与符号链接外跳
        if member.isdev():
            continue
        target = os.path.abspath(os.path.join(dest, member.name))
        if not target.startswith(dest_abs + os.sep) and target != dest_abs:
            continue
        if member.issym() or member.islnk():
            link_target = os.path.abspath(os.path.join(dest, member.name, "..", member.linkname))
            if not link_target.startswith(dest_abs):
                continue
        try:
            tar.extract(member, dest)
        except Exception:
            continue


def _safe_extract_zip(zf: zipfile.ZipFile, dest: str) -> None:
    """规避 path traversal 的 zip 解压。"""
    dest_abs = os.path.abspath(dest)
    for info in zf.infolist():
        # 跳过软链接（zip 一般不会带）
        # 直接解压并校验最终路径还在 dest 下
        target = os.path.abspath(os.path.join(dest, info.filename))
        if not target.startswith(dest_abs + os.sep) and target != dest_abs:
            continue
        try:
            zf.extract(info, dest)
        except Exception:
            continue


def _sniff_archive_kind(path: str) -> str:
    """根据文件头嗅探归档类型。

    返回 "zip" / "tar" / "unknown"。
    - zip: PK\\x03\\x04 (local file header) / PK\\x05\\x06 (eocd, empty)
    - tar: 兜底；最终 tarfile.open(\"r:*\") 自带 gzip/bzip2/xz 嗅探
    """
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return "unknown"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    return "tar"


def _strip_wheel_dist_info(extract_dir: str) -> None:
    """wheel 解包后顶层 `*.dist-info/` 是元数据，不删除（METADATA 可能有用），
    但当顶层只有 `<pkg>/` 一个代码目录时，把它的内容上提一层，
    与 sdist 解包后的目录形态保持一致，方便 entry_point / slicer 命中。

    具体规则：
    - 如果解包目录里既有 `<pkg>/__init__.py` 也有 `<pkg>-*.dist-info/`，
      则把 `<pkg>/` 内的子文件移到 extract_dir 顶层（保留 dist-info）。
    - 如果代码包目录有多个，则不上提，避免冲突。
    """
    if not os.path.isdir(extract_dir):
        return
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    code_dirs: List[str] = []
    has_dist_info = False
    for e in entries:
        full = os.path.join(extract_dir, e)
        if os.path.isdir(full):
            if e.endswith(".dist-info") or e.endswith(".data"):
                has_dist_info = True
                continue
            init_py = os.path.join(full, "__init__.py")
            if os.path.isfile(init_py):
                code_dirs.append(e)
    if not has_dist_info or len(code_dirs) != 1:
        return
    only = os.path.join(extract_dir, code_dirs[0])
    for item in os.listdir(only):
        src = os.path.join(only, item)
        dst = os.path.join(extract_dir, item)
        if os.path.exists(dst):
            dst = dst + "__nested"
        try:
            shutil.move(src, dst)
        except Exception:
            continue
    shutil.rmtree(only, ignore_errors=True)


def unpack_tarball(
    tarball: str,
    ecosystem: str,
    workdir: str,
    package_name: Optional[str] = None,
) -> UnpackResult:
    """将 tarball 解压到 workdir/<pkg>@<ver>/ 并做生态规范化。

    package_name: 可选覆盖（来自外部的 "name@version"）；否则由 tarball 文件名推断。
    """
    base = os.path.basename(tarball)
    if base.endswith(".tar.gz"):
        stem = base[:-7]
    elif base.endswith(".tgz"):
        stem = base[:-4]
    else:
        stem = os.path.splitext(base)[0]

    pkg = package_name or stem
    # 避免非法目录字符
    safe_pkg = pkg.replace("/", "__").replace(" ", "_")
    extract_dir = os.path.join(workdir, f"{safe_pkg}")

    # 同名冲突 -> 加 hash 后缀
    if os.path.exists(extract_dir):
        h = hashlib.sha1(tarball.encode()).hexdigest()[:8]
        extract_dir = f"{extract_dir}__{h}"

    os.makedirs(extract_dir, exist_ok=True)

    result = UnpackResult(
        package=pkg,
        ecosystem=ecosystem,
        tarball=tarball,
        extract_dir=extract_dir,
    )

    try:
        result.raw_sha1 = _sha1_of_file(tarball)
    except Exception as e:
        result.errors.append(f"sha1_failed: {e}")

    # 改进 ①（v2）：先嗅探归档类型，wheel/zip 走 zipfile，其它走 tarfile。
    # PyPI 数据集里大量 typosquat 包文件名是 *.tar.gz 但实际是 wheel zip。
    kind = _sniff_archive_kind(tarball)
    extract_ok = False

    if kind == "zip":
        try:
            with zipfile.ZipFile(tarball, "r") as zf:
                _safe_extract_zip(zf, extract_dir)
            extract_ok = True
        except Exception as e:
            result.errors.append(f"zip_extract_failed: {e}")

    if not extract_ok:
        # 兜底：无论嗅探结果，都尝试一次 tarfile（应对极端误判 / 嗅探失败）
        try:
            with tarfile.open(tarball, "r:*") as tar:
                _safe_extract(tar, extract_dir)
            extract_ok = True
        except Exception as e:
            # 只有当 zip 也失败时，才把 tar 失败也记下
            if kind != "zip":
                result.errors.append(f"extract_failed: {e}")

    if not extract_ok:
        return result

    if ecosystem == "npm":
        _strip_leading_pkg_dir(extract_dir)
    elif ecosystem == "pypi" and kind == "zip":
        # wheel 解包后把 <pkg>/ 内容上提，让 entry_point / slicer 命中 __init__.py
        _strip_wheel_dist_info(extract_dir)

    # 统计
    fc, bc = 0, 0
    for root, _dirs, files in os.walk(extract_dir):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                bc += os.path.getsize(fp)
                fc += 1
            except OSError:
                continue
    result.file_count = fc
    result.byte_count = bc
    return result
