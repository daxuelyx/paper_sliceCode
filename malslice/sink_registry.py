"""§4.6 SinkRegistry：NPM / PyPI 敏感 API 规则库。"""
from __future__ import annotations

import csv
import os
from typing import Dict, Set


# ==============================  NPM  ==============================

NPM_EXTRA_SINKS: Set[str] = {
    # 代码执行
    "eval", "Function", "new Function",
    "vm.runInNewContext", "vm.runInThisContext",
    "vm.Script", "vm.compileFunction",
    # 子进程
    "child_process.exec", "child_process.execSync",
    "child_process.execFile", "child_process.execFileSync",
    "child_process.spawn", "child_process.spawnSync",
    "child_process.fork",
    # 网络
    "fetch", "XMLHttpRequest",
    "http.request", "http.get",
    "https.request", "https.get",
    "dns.lookup",
    "net.createConnection", "net.connect",
    # 文件 / 凭据 / 持久化
    "fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync",
    "fs.readFile", "fs.readFileSync",
    "fs.createWriteStream", "fs.createReadStream",
    "os.homedir", "os.tmpdir", "os.userInfo",
    # 反射
    "Reflect.get", "Reflect.apply", "Reflect.construct",
    # 剪贴板等
    "clipboardy.read", "clipboardy.write",
}


# 接收者为"敏感模块"时，obj[var]() 这种动态属性访问应触发 dynamic Sink 探针
NPM_SENSITIVE_MODULES: Set[str] = {
    "child_process", "fs", "net", "http", "https", "dns", "os",
    "vm", "process", "crypto", "zlib", "tls", "cluster",
    "require",  # require(var) 本身
}


NPM_REFLECTION_APIS: Set[str] = {
    "Reflect.get", "Reflect.apply", "Reflect.construct",
    "Function", "new Function",
    "vm.compileFunction", "vm.Script",
}


def load_npm_sinks(sensitive_csv: str = "") -> Set[str]:
    """从 MalTracker/sensitiveFunc.csv 加载基础 Sink，并合并增补。"""
    sinks: Set[str] = set(NPM_EXTRA_SINKS)
    if sensitive_csv and os.path.isfile(sensitive_csv):
        try:
            with open(sensitive_csv, "r", encoding="utf-8") as f:
                for row in csv.reader(f):
                    if not row:
                        continue
                    name = row[0].strip()
                    if name:
                        sinks.add(name)
        except Exception:
            pass
    return sinks


# ==============================  PyPI  ==============================

PY_SINKS_BY_CATEGORY: Dict[str, Set[str]] = {
    "exec": {
        "os.system", "os.popen",
        "subprocess.Popen", "subprocess.run", "subprocess.call",
        "subprocess.check_output", "subprocess.check_call",
        "subprocess.getoutput", "subprocess.getstatusoutput",
        "exec", "eval", "compile",
        "pty.spawn",
        "commands.getoutput", "commands.getstatusoutput",
    },
    "reflection": {
        "getattr", "setattr",
        "__import__", "importlib.import_module", "importlib.__import__",
        "operator.attrgetter", "operator.methodcaller",
        "types.FunctionType",
    },
    "network": {
        "socket.socket", "socket.create_connection",
        "urllib.request.urlopen", "urllib.urlopen",
        "urllib3.PoolManager",
        "requests.get", "requests.post", "requests.put",
        "requests.request", "requests.patch", "requests.delete",
        "http.client.HTTPConnection", "http.client.HTTPSConnection",
        "ftplib.FTP", "smtplib.SMTP", "telnetlib.Telnet",
    },
    "fs_persist": {
        "shutil.copy", "shutil.copyfile", "shutil.move",
        "os.chmod", "os.rename", "os.replace",
        "os.symlink", "os.link",
    },
    "deserialize": {
        "pickle.loads", "pickle.load",
        "marshal.loads", "marshal.load",
        "yaml.load",
        "dill.loads", "dill.load",
        "shelve.open",
    },
    "env_secret": {
        "keyring.get_password",
        "getpass.getpass",
        "platform.node", "platform.uname",
        "os.environ",  # 下游会根据键名做 TOKEN/KEY 过滤
    },
}

PY_REFLECTION_APIS: Set[str] = set(PY_SINKS_BY_CATEGORY["reflection"])

PY_SENSITIVE_MODULES: Set[str] = {
    "os", "subprocess", "socket", "requests", "urllib", "urllib3",
    "importlib", "pickle", "marshal", "shutil", "http", "ftplib",
    "smtplib", "telnetlib", "ssl", "ctypes",
}


def load_py_sinks() -> Set[str]:
    out: Set[str] = set()
    for s in PY_SINKS_BY_CATEGORY.values():
        out |= s
    return out


# ==============================  Meta  =============================

SENSITIVE_PATH_FRAGMENTS = {
    ".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/config",
    ".bashrc", ".bash_profile", ".zshrc", ".profile",
    ".npmrc", ".pypirc", ".aws/credentials",
    "crontab", "/etc/cron", "/etc/systemd",
}

SECRET_ENV_KEY_HINTS = {
    "TOKEN", "KEY", "SECRET", "PASS", "PASSWORD", "API_KEY",
    "NPM_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS", "AWS_SECRET",
}
