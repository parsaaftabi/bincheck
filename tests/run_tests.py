#!/usr/bin/env python3
"""End-to-end tests for bincheck.

Compiles small C fixtures in different hardening configurations and checks
that bincheck reports the expected verdicts and exit codes. PE coverage uses
the llvm-mingw cross compiler when it is installed and skips cleanly when
it is not.
"""

import json
import os
import random
import shutil
import subprocess
import sys

FAILURES = []
PASSES = []
SKIPS = []


def record(ok, name, detail=""):
    if ok:
        PASSES.append(name)
        print(f"PASS {name}")
    else:
        FAILURES.append(name)
        print(f"FAIL {name} {detail}")


def skip(name, reason):
    SKIPS.append(name)
    print(f"SKIP {name} ({reason})")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def run_bincheck(binary, *args):
    return run([binary, *args])


def check_status(report, name):
    for entry in report.get("hardening", []):
        if entry["name"] == name:
            return entry["status"]
    return None


def find_host_compiler():
    for cand in (os.environ.get("CC"), "cc", "gcc", "clang"):
        if cand and shutil.which(cand):
            return shutil.which(cand)
    return None


def find_mingw_compiler():
    home = os.path.expanduser("~")
    fixed = os.path.join(
        home,
        "workspace/tools/llvm-mingw-20250114-ucrt-ubuntu-20.04-x86_64/bin",
        "x86_64-w64-mingw32-g++",
    )
    if os.path.isfile(fixed) and os.access(fixed, os.X_OK):
        return fixed
    for cand in ("x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-clang++"):
        found = shutil.which(cand)
        if found:
            return found
    return None


def find_mingw_compiler32():
    home = os.path.expanduser("~")
    fixed = os.path.join(
        home,
        "workspace/tools/llvm-mingw-20250114-ucrt-ubuntu-20.04-x86_64/bin",
        "i686-w64-mingw32-g++",
    )
    if os.path.isfile(fixed) and os.access(fixed, os.X_OK):
        return fixed
    for cand in ("i686-w64-mingw32-g++", "i686-w64-mingw32-clang++"):
        found = shutil.which(cand)
        if found:
            return found
    return None


def elf_fixture_tests(binary, work, fixture_src):
    # The ELF fixtures need a host compiler that targets ELF. On a
    # Windows host the available gcc targets PE and rejects the ELF
    # linker flags (-z relro and friends), so these cases run on the
    # Linux CI job only. The parser still gets exercised on Windows
    # through the PE fixtures and the self tests.
    if sys.platform.startswith("win"):
        skip("elf fixtures", "host compiler targets PE on Windows")
        return
    cc = find_host_compiler()
    if cc is None:
        skip("elf fixtures", "no host C compiler found")
        return

    hardened = os.path.join(work, "fixture-hardened")
    out = run([
        cc, "-O2", "-pie", "-fPIE", "-fstack-protector-strong",
        "-Wl,-z,relro,-z,now", fixture_src, "-o", hardened,
    ])
    if out.returncode != 0:
        record(False, "build hardened fixture", out.stderr.strip())
        return
    record(True, "build hardened fixture")

    proc = run_bincheck(binary, hardened)
    record(proc.returncode == 0, "hardened fixture exits 0",
           f"exit {proc.returncode}")
    record("Format: ELF" in proc.stdout, "hardened fixture format line")
    record("libc.so" in proc.stdout, "hardened fixture lists libc")

    proc = run_bincheck(binary, "--strict", hardened)
    record(proc.returncode == 0, "hardened fixture passes strict",
           f"exit {proc.returncode}")

    proc = run_bincheck(binary, "--json", hardened)
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        record(False, "hardened fixture json parses", str(exc))
        return
    record(report.get("format") == "ELF", "json format is ELF")
    record(report.get("version") == "0.2.1", "json version is 0.2.1")
    record(report.get("architecture") == "x86-64", "json architecture")
    record(check_status(report, "pie") == "pass", "json pie passes")
    record(check_status(report, "nx-stack") == "pass", "json nx-stack passes")
    record(check_status(report, "relro") == "pass", "json relro passes")
    record(check_status(report, "full-relro") == "pass",
           "json full-relro passes")
    record(check_status(report, "stack-canary") == "pass",
           "json stack-canary passes")
    record(check_status(report, "rpath") == "n/a",
           "hardened fixture rpath is n/a without an rpath tag")
    record(any("libc" in lib for lib in report.get("needed", [])),
           "json needed lists libc")

    # Fortify: this gcc predefines _FORTIFY_SOURCE at -O2, so the pass
    # build states it outright and the fail build undefines it. The fail
    # build keeps the stack protector, so the canary check still passes
    # and only fortify flips.
    fortified = os.path.join(work, "fixture-fortified")
    out = run([
        cc, "-O2", "-D_FORTIFY_SOURCE=2", "-pie", "-fPIE",
        "-fstack-protector-strong", fixture_src, "-o", fortified,
    ])
    if out.returncode != 0:
        record(False, "build fortified fixture", out.stderr.strip())
        return
    record(True, "build fortified fixture")
    proc = run_bincheck(binary, "--json", fortified)
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        record(False, "fortified fixture json parses", str(exc))
        return
    record(check_status(report, "fortify") == "pass",
           "fortified fixture fortify passes")

    unfortified = os.path.join(work, "fixture-unfortified")
    out = run([
        cc, "-O2", "-U_FORTIFY_SOURCE", "-pie", "-fPIE",
        "-fstack-protector-strong", fixture_src, "-o", unfortified,
    ])
    if out.returncode != 0:
        record(False, "build unfortified fixture", out.stderr.strip())
        return
    record(True, "build unfortified fixture")
    proc = run_bincheck(binary, "--json", unfortified)
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        record(False, "unfortified fixture json parses", str(exc))
        return
    record(check_status(report, "fortify") == "fail",
           "unfortified fixture fortify fails")
    record(check_status(report, "stack-canary") == "pass",
           "unfortified fixture canary still passes")

    # RPATH: an absolute entry and a $ORIGIN entry pass, a plain
    # relative entry fails.
    for label, rpath, want in (
        ("absolute", "/tmp/x", "pass"),
        ("origin", "$ORIGIN/lib", "pass"),
        ("relative", "lib", "fail"),
    ):
        target = os.path.join(work, f"fixture-rpath-{label}")
        out = run([
            cc, "-O2", "-pie", "-fPIE", fixture_src, "-o", target,
            f"-Wl,-rpath,{rpath}",
        ])
        if out.returncode != 0:
            record(False, f"build rpath {label} fixture",
                   out.stderr.strip())
            continue
        record(True, f"build rpath {label} fixture")
        proc = run_bincheck(binary, "--json", target)
        try:
            report = json.loads(proc.stdout)
        except ValueError as exc:
            record(False, f"rpath {label} fixture json parses", str(exc))
            continue
        record(check_status(report, "rpath") == want,
               f"rpath {label} fixture reports {want}")

    weak = os.path.join(work, "fixture-weak")
    out = run([
        cc, "-O2", "-no-pie", "-fno-stack-protector",
        "-Wl,-z,norelro", fixture_src, "-o", weak,
    ])
    if out.returncode != 0:
        record(False, "build weak fixture", out.stderr.strip())
        return
    record(True, "build weak fixture")

    proc = run_bincheck(binary, "--json", weak)
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        record(False, "weak fixture json parses", str(exc))
        return
    record(check_status(report, "pie") == "fail", "weak fixture pie fails")
    record(check_status(report, "stack-canary") == "fail",
           "weak fixture stack-canary fails")
    record(check_status(report, "relro") == "fail",
           "weak fixture relro fails")

    proc = run_bincheck(binary, weak)
    record(proc.returncode == 0, "weak fixture exits 0 without strict",
           f"exit {proc.returncode}")
    proc = run_bincheck(binary, "--strict", weak)
    record(proc.returncode == 1, "weak fixture fails strict with exit 1",
           f"exit {proc.returncode}")


def pe_fixture_tests(binary, work, fixture_src):
    cxx = find_mingw_compiler()
    if cxx is None:
        skip("pe fixture", "llvm-mingw compiler not found")
        return
    exe = os.path.join(work, "fixture-pe.exe")
    out = run([cxx, "-static", fixture_src, "-o", exe])
    if out.returncode != 0:
        record(False, "build pe fixture", out.stderr.strip())
        return
    record(True, "build pe fixture")

    proc = run_bincheck(binary, "--json", exe)
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        record(False, "pe fixture json parses", str(exc))
        return
    record(report.get("format") == "PE", "pe json format is PE")
    record(report.get("architecture") == "x86-64", "pe json architecture")
    record(len(report.get("sections", [])) > 0, "pe json lists sections")
    record(any("msvcrt" in lib.lower() or "kernel32" in lib.lower()
               or "ucrtbase" in lib.lower() or "api-ms-win-crt" in lib.lower()
               for lib in report.get("imports", [])),
           "pe json lists imports")
    for name in ("aslr", "high-entropy-aslr", "dep-nx", "cfg"):
        record(check_status(report, name) in ("pass", "fail"),
               f"pe json reports {name}")
    # The llvm-mingw linker writes a load config with a zero
    # SecurityCookie field, so gs-cookie reads fail on that fixture.
    # A mingw linker running on a Windows host may write no load
    # config at all, and then the check reports n/a. Either way the
    # check must be present with a valid status. safe-seh is n/a on
    # 64-bit files.
    record(check_status(report, "gs-cookie") in ("pass", "fail", "n/a"),
           "pe json reports gs-cookie")
    record(check_status(report, "safe-seh") == "n/a",
           "pe 64-bit safe-seh is n/a")

    proc = run_bincheck(binary, exe)
    record(proc.returncode == 0, "pe fixture exits 0",
           f"exit {proc.returncode}")

    cxx32 = find_mingw_compiler32()
    if cxx32 is None:
        skip("pe32 fixture", "llvm-mingw 32-bit compiler not found")
    else:
        exe32 = os.path.join(work, "fixture-pe32.exe")
        out = run([cxx32, "-static", fixture_src, "-o", exe32])
        if out.returncode != 0:
            record(False, "build pe32 fixture", out.stderr.strip())
        else:
            record(True, "build pe32 fixture")
            proc = run_bincheck(binary, "--json", exe32)
            try:
                report32 = json.loads(proc.stdout)
            except ValueError as exc:
                record(False, "pe32 fixture json parses", str(exc))
                report32 = None
            if report32 is not None:
                record(report32.get("format") == "PE",
                       "pe32 json format is PE")
                record(report32.get("bits") == 32, "pe32 json bits is 32")
                record(check_status(report32, "safe-seh")
                       in ("pass", "fail", "n/a"),
                       "pe32 json reports safe-seh")
                record(check_status(report32, "gs-cookie")
                       in ("pass", "fail", "n/a"),
                       "pe32 json reports gs-cookie")

    with open(exe, "rb") as fh:
        head = fh.read(32)
    truncated = os.path.join(work, "truncated-pe")
    with open(truncated, "wb") as fh:
        fh.write(head)
    proc = run_bincheck(binary, truncated)
    record(proc.returncode == 2, "truncated pe exits 2",
           f"exit {proc.returncode}")


def malformed_tests(binary, work):
    empty = os.path.join(work, "empty")
    with open(empty, "wb"):
        pass
    proc = run_bincheck(binary, empty)
    record(proc.returncode == 2, "empty file exits 2",
           f"exit {proc.returncode}")

    rng = random.Random(20261112)
    blob = os.path.join(work, "random")
    with open(blob, "wb") as fh:
        fh.write(b"NOPE")
        fh.write(bytes(rng.randrange(256) for _ in range(508)))
    proc = run_bincheck(binary, blob)
    record(proc.returncode == 2, "random bytes exit 2",
           f"exit {proc.returncode}")

    target = "/bin/ls" if os.path.isfile("/bin/ls") else binary
    with open(target, "rb") as fh:
        head = fh.read(20)
    truncated = os.path.join(work, "truncated-elf")
    with open(truncated, "wb") as fh:
        fh.write(head)
    proc = run_bincheck(binary, truncated)
    record(proc.returncode == 2, "truncated elf header exits 2",
           f"exit {proc.returncode}")

    proc = run_bincheck(binary, os.path.join(work, "does-not-exist"))
    record(proc.returncode == 2, "missing file exits 2",
           f"exit {proc.returncode}")


def self_tests(binary):
    proc = run_bincheck(binary, "--version")
    record(proc.returncode == 0 and proc.stdout.strip() == "bincheck 0.2.1",
           "--version prints bincheck 0.2.1",
           f"exit {proc.returncode} out {proc.stdout.strip()!r}")

    proc = run_bincheck(binary, "--json", binary)
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        record(False, "bincheck reads itself", str(exc))
        return
    record(report.get("format") in ("ELF", "PE"), "bincheck reads itself")
    record(proc.returncode == 0, "bincheck on itself exits 0",
           f"exit {proc.returncode}")


def main():
    if len(sys.argv) != 3:
        print("usage: run_tests.py <bincheck> <workdir>", file=sys.stderr)
        return 2
    binary = os.path.abspath(sys.argv[1])
    work = sys.argv[2]
    os.makedirs(work, exist_ok=True)
    fixture_src = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixture.c")

    elf_fixture_tests(binary, work, fixture_src)
    pe_fixture_tests(binary, work, fixture_src)
    malformed_tests(binary, work)
    self_tests(binary)

    print(f"results: {len(PASSES)} passed, {len(FAILURES)} failed, "
          f"{len(SKIPS)} skipped")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
