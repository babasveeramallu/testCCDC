#!/usr/bin/env python3
"""Apply the CCDC Debian-style PAM/account policy to a supplied root tree."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import tempfile
from pathlib import Path

FILES = (
    Path("etc/pam.d/common-auth"),
    Path("etc/pam.d/common-account"),
    Path("etc/pam.d/common-password"),
    Path("etc/login.defs"),
)


def atomic_write(path: Path, content: str) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        shutil.copystat(path, tmp_name, follow_symlinks=False)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def set_login_value(text: str, key: str, value: int) -> str:
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.M)
    replacement = f"{key}\t{value}"
    if pattern.search(text):
        return pattern.sub(replacement, text, count=1)
    return text.rstrip() + f"\n{replacement}\n"


def apply(root: Path, backup_dir: Path) -> None:
    paths = [root / relative for relative in FILES]
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Unsupported/missing PAM file (symlinks are refused): {path}")
    common_auth, common_account, common_password, login_defs = [p.read_text(encoding="utf-8") for p in paths]
    auth_unix = re.compile(r"^\s*auth\s+\[success=1\s+default=ignore\]\s+pam_unix\.so.*$", re.M)
    auth_matches = list(auth_unix.finditer(common_auth))
    if len(auth_matches) != 1:
        raise RuntimeError("common-auth is not the recognized Debian simple pam_unix stack; no files edited")
    extra_auth = [line for line in common_auth.splitlines() if re.match(r"^\s*auth\s+", line) and not any(module in line for module in ("pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_faillock.so", "pam_cap.so"))]
    if extra_auth:
        raise RuntimeError("common-auth has additional auth providers; refusing to reorder this PAM stack")
    if not re.search(r"^\s*account\s+.*pam_unix\.so", common_account, re.M):
        raise RuntimeError("common-account has no pam_unix entry; unsupported PAM stack")
    password_unix = re.compile(r"^\s*password\s+([^\n]*pam_unix\.so[^\n]*)$", re.M)
    if len(list(password_unix.finditer(common_password))) != 1:
        raise RuntimeError("common-password must have exactly one pam_unix entry")

    common_auth = re.sub(r"(?m)^\s*auth\s+.*pam_faillock\.so.*\n", "", common_auth)
    match = auth_unix.search(common_auth)
    unix_line = match.group(0).replace("success=1", "success=1", 1)
    common_auth = common_auth[:match.start()] + "auth required pam_faillock.so preauth silent deny=5 unlock_time=1800\n" + unix_line + "\nauth [default=die] pam_faillock.so authfail deny=5 unlock_time=1800\nauth sufficient pam_faillock.so authsucc deny=5 unlock_time=1800\n" + common_auth[match.end():]
    deny = re.search(r"^\s*auth\s+requisite\s+pam_deny\.so.*$", common_auth, re.M)
    if not deny:
        raise RuntimeError("common-auth has no recognized requisite pam_deny entry")

    common_account = re.sub(r"(?m)^\s*account\s+.*pam_faillock\.so.*\n", "", common_account)
    unix_account = re.search(r"^\s*account\s+.*pam_unix\.so.*$", common_account, re.M)
    common_account = common_account[:unix_account.start()] + "account required pam_faillock.so deny=5 unlock_time=1800\n" + common_account[unix_account.start():]

    common_password = re.sub(r"(?m)^\s*password\s+.*pam_pwquality\.so.*\n", "", common_password)
    password_match = password_unix.search(common_password)
    unix_password = password_match.group(1)
    if not re.search(r"\buse_authtok\b", unix_password):
        unix_password += " use_authtok"
    if not re.search(r"\bremember=\d+", unix_password):
        unix_password += " remember=5"
    else:
        unix_password = re.sub(r"\bremember=\d+", "remember=5", unix_password)
    common_password = common_password[:password_match.start()] + "password requisite pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\npassword " + unix_password + common_password[password_match.end():]

    updated = [common_auth, common_account, common_password]
    updated.append(set_login_value(set_login_value(set_login_value(login_defs, "PASS_MAX_DAYS", 60), "PASS_MIN_DAYS", 7), "PASS_WARN_AGE", 7))
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for path in paths:
        shutil.copy2(path, backup_dir / path.name)
    try:
        for path, text in zip(paths, updated):
            atomic_write(path, text)
        for path in paths[:3]:
            if "pam_faillock.so" not in path.read_text(encoding="utf-8") and path.name != "common-password":
                raise RuntimeError(f"faillock setting verification failed: {path}")
        if "pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" not in paths[2].read_text(encoding="utf-8"):
            raise RuntimeError("pwquality verification failed")
        verify_defs = paths[3].read_text(encoding="utf-8")
        for key, expected in (("PASS_MAX_DAYS", 60), ("PASS_MIN_DAYS", 7), ("PASS_WARN_AGE", 7)):
            if not re.search(rf"(?m)^\s*{key}\s+{expected}\s*$", verify_defs):
                raise RuntimeError(f"login.defs verification failed: {key}")
    except Exception:
        for original in paths:
            shutil.copy2(backup_dir / original.name, original)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/"), help="Root directory (useful for isolated fixture tests)")
    parser.add_argument("--backup-dir", type=Path, required=True)
    args = parser.parse_args()
    apply(args.root.resolve(), args.backup_dir.resolve())
    print(f"PAM/account policy applied and verified; backups={args.backup_dir}")


if __name__ == "__main__":
    main()
