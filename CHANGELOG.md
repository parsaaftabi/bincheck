# Changelog

## 0.2.0, 2026-11-14

- ELF: new `fortify` check. It passes when a `*_chk` function such as `__memcpy_chk` or `__printf_chk` appears in the dynamic symbols. `__stack_chk_fail` does not count, it is the canary helper. A file with a dynamic symbol table and no fortified calls fails. A file with no dynamic symbol table reports n/a.
- ELF: new `rpath` check. It reads DT_RPATH and DT_RUNPATH from the dynamic string table. Absolute entries and entries that start with `$ORIGIN` pass. An empty entry fails, and a relative entry without `$ORIGIN` fails. Files with neither tag report n/a.
- PE: new `gs-cookie` check. It reads the SecurityCookie field of the load config directory and passes when the field is non-zero. The offsets are 60 in the 32-bit load config struct and 88 in the 64-bit struct, counted in bytes from the start of the struct. A field is read only when the directory size covers it.
- PE: new `safe-seh` check for 32-bit files. It passes when the load config holds an SEHandlerTable with at least one handler, or when the load config GuardFlags field is set. 64-bit files report n/a.
- `bincheck --version` prints `bincheck 0.2.0`.
- JSON output has a top level `version` field.
- Tests cover the new checks. The ELF cases build fortified and unfortified fixtures and three rpath variants. The PE cases build 32-bit and 64-bit fixtures with the mingw cross compiler and skip when it is absent.
- One test note: this machine's gcc predefines `_FORTIFY_SOURCE` at -O2, so the unfortified fixture builds with `-U_FORTIFY_SOURCE`. Without that flag the fail case would pass for the wrong reason.

## 0.1.0

First release.

- Reads ELF files, 32-bit and 64-bit, little-endian. Reports sections, program headers, DT_NEEDED libraries and the entry point.
- Reads PE files, PE32 and PE32+. Reports sections, imported DLLs, the entry point and whether a load config directory exists.
- ELF checks: pie, nx-stack, relro, full-relro, stack-canary.
- PE checks from DllCharacteristics: aslr, high-entropy-aslr, dep-nx, cfg.
- Human readable output and `--json` output.
- `--strict` exits 1 when an applicable check fails. Parse errors exit 2.
- Every offset and size read is bounds-checked. Truncated and corrupt files get an error message, not a crash.
