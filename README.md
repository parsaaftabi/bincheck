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
  fortify           PASS  fortified calls in dynamic symbols, e.g. __snprintf_chk
  rpath             N/A   no DT_RPATH or DT_RUNPATH entry
```

The same build reads its own binary:

```console
$ bincheck build/bincheck
File: build/bincheck
Format: ELF 64-bit (ET_DYN)
Architecture: x86-64
Entry point: 0x6e40

Sections (33):
  .interp  size 28  at 0x318
  .dynsym  size 1272  at 0x3e0
  .text  size 68557  at 0x2540
  ...

Program headers (13):
  PT_LOAD  flags R-X  file size 69917  at 0x2000
  PT_GNU_STACK  flags RW-  file size 0  at 0x0
  PT_GNU_RELRO  flags R--  file size 992  at 0x17c20
  ...

Needed libraries (3):
  libstdc++.so.6
  libgcc_s.so.1
  libc.so.6

Hardening:
  pie               PASS  type is ET_DYN
  nx-stack          PASS  PT_GNU_STACK lacks the execute flag
  relro             PASS  PT_GNU_RELRO present, BIND_NOW set
  full-relro        PASS  BIND_NOW set, relocations resolve at load time
  stack-canary      PASS  __stack_chk_fail found in dynamic symbols
  fortify           PASS  fortified calls in dynamic symbols, e.g. __snprintf_chk
  rpath             N/A   no DT_RPATH or DT_RUNPATH entry
```

PE files get the same treatment. This run reads a Windows build of bincheck itself:

```console
$ bincheck bincheck.exe
File: bincheck.exe
Format: PE 64-bit (PE32+)
Architecture: x86-64
Entry point: 0x1380

Sections (13):
  .text  size 575910  at 0x1000  characteristics 0x60000020
  .rdata  size 147228  at 0x8e000  characteristics 0x40000040
  ...

Imported libraries (12):
  KERNEL32.dll
  api-ms-win-crt-stdio-l1-1-0.dll
  ...

Load config directory: present

Hardening:
  aslr              PASS  DYNAMIC_BASE set, image can load at a random base
  high-entropy-aslr PASS  HIGH_ENTROPY_VA set, 64-bit address space is used for ASLR
  dep-nx            PASS  NX_COMPAT set, data pages stay non-executable
  cfg               FAIL  GUARD_CF clear, no Control Flow Guard
  gs-cookie         FAIL  load config SecurityCookie is zero
  safe-seh          N/A   64-bit PE reads handlers from .pdata, no SEHandlerTable
```

The `gs-cookie` line above is a real read, not a guess at the toolchain. The mingw linker writes a load config and leaves the SecurityCookie field at zero in the file. MSVC writes the address of its cookie variable into that field, and bincheck reports pass for those files.

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
bincheck --version         # print "bincheck 0.2.1"
```

The JSON report carries a top level `version` field with the bincheck version, so a script can pin the output shape it reads.

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
| fortify | At least one `*_chk` function, such as `__memcpy_chk`, appears in the dynamic symbol table. `__stack_chk_fail` is the canary helper and does not count. Reports n/a when the file has no dynamic symbol table |
| rpath | Every DT_RPATH and DT_RUNPATH entry is absolute or starts with `$ORIGIN`. An empty entry or a relative entry without `$ORIGIN` fails. Reports n/a when neither tag exists |

Four PE checks read the DllCharacteristics field of the optional header:

| Check | Flag |
|---|---|
| aslr | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
| high-entropy-aslr | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
| dep-nx | IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
| cfg | IMAGE_DLLCHARACTERISTICS_GUARD_CF |

Two PE checks read the load config directory. A field is read only when the directory size covers it:

| Check | Pass condition |
|---|---|
| gs-cookie | The load config SecurityCookie field is non-zero. Fails when a load config exists and the field is zero. Reports n/a when there is no load config |
| safe-seh | 32-bit files only. The load config holds an SEHandlerTable with at least one handler, or its GuardFlags field is set. 64-bit files report n/a, because their handlers come from .pdata |

A check that cannot apply to a file reports `n/a` and never fails a `--strict` run. ELF support covers 32-bit and 64-bit files. Only little-endian files are accepted. PE support covers PE32 and PE32+.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The file parsed. With `--strict`, every applicable check passed |
| 1 | `--strict` was given and at least one applicable check failed |
| 2 | The file could not be opened or parsed |

## License

MIT. See [LICENSE](LICENSE).
