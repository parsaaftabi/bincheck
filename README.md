# bincheck

[![CI](https://github.com/parsaaftabi/bincheck/actions/workflows/ci.yml/badge.svg)](https://github.com/parsaaftabi/bincheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Read an ELF or PE binary and get its layout and hardening state in one run. Zero dependencies, one C++17 binary.

```console
$ bincheck /bin/ls
File: /bin/ls
Format: ELF 64-bit (ET_DYN)
Architecture: x86-64
Entry point: 0x6d30

Sections (31):
  .interp  size 28  at 0x318
  .dynsym  size 3072  at 0x400
  .text  size 82370  at 0x4d70
  ...

Program headers (13):
  PT_LOAD  flags R-X  file size 85825  at 0x4000
  PT_GNU_STACK  flags RW-  file size 0  at 0x0
  PT_GNU_RELRO  flags R--  file size 4304  at 0x21f30
  ...

Needed libraries (2):
  libselinux.so.1
  libc.so.6

Hardening:
  pie               PASS  type is ET_DYN
  nx-stack          PASS  PT_GNU_STACK lacks the execute flag
  relro             PASS  PT_GNU_RELRO present, BIND_NOW set
  full-relro        PASS  BIND_NOW set, relocations resolve at load time
  stack-canary      PASS  __stack_chk_fail found in dynamic symbols
```

PE files get the same treatment. This run reads a Windows build of bincheck itself:

```console
$ bincheck bincheck.exe
File: bincheck.exe
Format: PE 64-bit (PE32+)
Architecture: x86-64
Entry point: 0x1380

Load config directory: present

Hardening:
  aslr              PASS  DYNAMIC_BASE set, image can load at a random base
  high-entropy-aslr PASS  HIGH_ENTROPY_VA set, 64-bit address space is used for ASLR
  dep-nx            PASS  NX_COMPAT set, data pages stay non-executable
  cfg               FAIL  GUARD_CF clear, no Control Flow Guard
```

## Why

Hardening flags are set by compiler and linker options, and they fail silently. A build that drops `-fstack-protector-strong` or `-Wl,-z,now` still compiles, still runs, and ships with a weaker binary. `checksec` covers ELF files on Linux and leaves PE files to other tools. bincheck reads both formats with one set of commands, prints JSON for scripts, and returns an exit code a CI job can gate on.

The parser bounds-checks every offset and size it reads. A truncated or corrupt file gets a clean error and exit code 2. The parser never reads out of bounds and never crashes on bad input.

## Build

You need CMake 3.20 or newer and a C++17 compiler. There are no other dependencies.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

The binary lands at `build/bincheck` (`build\Release\bincheck.exe` on Windows).

## Usage

```bash
bincheck <file>            # human readable report
bincheck --json <file>     # JSON report for scripts
bincheck --strict <file>   # exit 1 when any check fails
```

Use `--strict` as a CI gate:

```bash
bincheck --strict ./app || echo "hardening regression"
```

## Checks

ELF checks:

| Check | Pass condition |
|---|---|
| pie | File type is ET_DYN, not ET_EXEC |
| nx-stack | A PT_GNU_STACK segment exists and lacks the execute flag |
| relro | A PT_GNU_RELRO segment exists |
| full-relro | BIND_NOW is set in DT_FLAGS or DT_FLAGS_1, or a DT_BIND_NOW entry exists |
| stack-canary | `__stack_chk_fail` appears in the dynamic symbol table |

PE checks read the DllCharacteristics field of the optional header:

| Check | Flag |
|---|---|
| aslr | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
| high-entropy-aslr | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
| dep-nx | IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
| cfg | IMAGE_DLLCHARACTERISTICS_GUARD_CF |

A check that cannot apply to a file reports `n/a` and never fails a `--strict` run. ELF support covers 32-bit and 64-bit files. Only little-endian files are accepted. PE support covers PE32 and PE32+.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The file parsed. With `--strict`, every applicable check passed |
| 1 | `--strict` was given and at least one applicable check failed |
| 2 | The file could not be opened or parsed |

## License

MIT. See [LICENSE](LICENSE).
