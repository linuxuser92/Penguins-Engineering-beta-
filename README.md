# Penguins Engineering

> **⚠️ Beta software — v0.1.0**
>
> PE Linux is under active development and has **not** reached a stable
> release. The decoder is correct for the opcode families it supports, but
> large parts of the x86-64 instruction set are still missing (SSE/AVX,
> x87, string ops, `0xC6`/`0xC7` immediate moves, and many others). These
> appear in the output as one-byte `db 0xNN` lines rather than real
> mnemonics.
>
> Interfaces, CLI flags, output format, and internal headers may change
> without notice before v1.0. Do not rely on PE Linux as a replacement for
> `objdump`, `llvm-objdump`, or Ghidra in any production or security-
> critical workflow. Use it for learning, experimentation, and as a
> reference implementation.
>
> Bug reports and pull requests are welcome — see
> [Contributing](#contributing).

A minimal, dependency-free x86-64 ELF disassembler for Linux, written in
C++17.

PE Linux parses an ELF64 binary, walks its sections, and linearly
disassembles the machine code inside them. It's a teaching-grade engine,
not a replacement for `objdump` — but it produces correct, byte-for-byte
matching output for the opcode families it supports, and the source is
short enough to read end to end.

```
  ___           _                _____         _
 | _ \___ _ _  (_)__ _ _ _  ___  | ____|_  _ __(_)_ _  ___ _ _
 |  _/ -_) ' \ | / _` | ' \/ _ \ |  _|| || / _` | ' \/ -_) ' \
 |_| \___|_||_|_|\__, |_||_\___/ |_____|\_, \__, |_||_\___|_||_|
                 |___/                  |__/  |_/
```

---

## Installation

### Requirements

| Component | Minimum | Notes |
|---|---|---|
| OS | Any Linux with glibc | Kernel 3.x or later |
| Compiler | g++ ≥ 7 **or** clang++ ≥ 5 | Must support C++17 |
| Build tool | GNU make ≥ 4.0 | BSD make is untested |
| Disk | ~1 MB | Source + binary |
| Runtime deps | none | Statically self-contained |

No third-party libraries. No package manager required. No network access
needed after cloning.

### Build from source (recommended)

```bash
git clone https://github.com/<you>/PE-Linux.git
cd PE-Linux
make
```

The compiled binary is `./penguins-eng`. Verify it runs:

```bash
./penguins-eng --help
```

### System-wide install

```bash
sudo make install
```

This copies the binary to `/usr/local/bin/penguins-eng`. The rule is just
`install -m 0755 $(TARGET) /usr/local/bin/`, so if you prefer a different
prefix, run the command manually:

```bash
sudo install -m 0755 penguins-eng /usr/bin/penguins-eng
```

To uninstall:

```bash
sudo rm /usr/local/bin/penguins-eng
```

### Build with a different compiler

The Makefile uses `$(CXX)` and `$(CXXFLAGS)`, so both are overridable:

```bash
make CXX=clang++
make CXX=g++-13 CXXFLAGS="-std=c++17 -O3 -march=native"
```

### Build with debug symbols

```bash
make clean
make CXXFLAGS="-std=c++17 -g -O0 -fsanitize=address,undefined"
```

The resulting binary will abort on memory errors or undefined behavior,
which makes it useful when extending the decoder.

### Verifying the build

A quick smoke test:

```bash
./penguins-eng -n 5 /bin/ls
```

Expected output (first few lines):

```
File   : /bin/ls
Type   : DYN (PIE)
Entry  : 0x6a60
Section: .text

0000000000006a60: ...
...
```

If you see the banner and a handful of instructions, the build is good.

### Prebuilt binaries

There are **no** prebuilt binaries yet. Once the decoder reaches a stable
1.0, releases will be published under
[GitHub Releases](https://github.com/<you>/PE-Linux/releases) as static
x86-64 ELF binaries with SHA-256 checksums.

Until then, build from source. If you need a binary on a system without a
C++17 compiler, cross-compile elsewhere and copy the result over — PE Linux
has no runtime dependencies beyond glibc.

### Platform notes

- **Debian / Ubuntu / Mint** — works out of the box; `g++` and `make`
  come from `build-essential`.
- **Fedora / RHEL / CentOS** — install `gcc-c++` and `make` first.
- **Arch / Manjaro** — `base-devel` provides everything.
- **Alpine / musl** — build with `make CXX=g++` after installing
  `g++` and `make`; the resulting binary links against musl and runs
  only on musl systems unless you build statically
  (`make CXXFLAGS="-std=c++17 -static"`).
- **WSL2** — treat as Ubuntu; works identically.
- **macOS / BSD / Windows** — not supported. The ELF parser and the
  section-name lookup assume Linux conventions, and the Makefile uses GNU
  make extensions.

---

## Quick start

Disassemble `.text` of `/bin/ls`:

```bash
penguins-eng /bin/ls
```

Byte listing, first 40 instructions:

```bash
penguins-eng -l -n 40 /bin/ls
```

A specific address range:

```bash
penguins-eng -l -a 0x1cd87 -n 6 /bin/ls
```

```
000000000001cd87: 85 db                     test     ebx, ebx
000000000001cd89: 75 25                     jne      0x1cdb0
000000000001cd8b: 85 c0                     test     eax, eax
000000000001cd8d: 74 15                     je       0x1cda4
000000000001cd8f: 4d 85 f6                  test     r14, r14
000000000001cd92: 75 2b                     jne      0x1cdbf
```

Disassemble a different section:

```bash
penguins-eng -s .plt /bin/ls
```

---

## Features

- **ELF64 parsing** — section headers, section-name string table, virtual
  address ↔ file offset mapping.
- **x86-64 decoding** with full REX prefix support (`REX.W/R/X/B`), legacy
  prefixes (segment, operand-size, address-size, lock, rep), and ModRM +
  SIB addressing (including RIP-relative and disp32-only forms).
- **Opcode coverage** for the common integer instruction set:
  - `mov` (register, immediate, r/m, moffs), `lea`, `push`, `pop`, `xchg`
  - `add`, `or`, `adc`, `sbb`, `and`, `sub`, `xor`, `cmp` (all r/m and
    accumulator-imm forms, including the short `04/05/0C/0D/…` encodings)
  - `test`, `imul`, `mul`, `div`, `idiv`, `neg`, `not`
  - `inc`, `dec`, `shl`, `shr`, `sar`, `rol`, `ror`, `rcl`, `rcr`
  - `jmp` (rel8/rel32), `Jcc` (rel8/rel32), `call` (rel32), `ret`, `leave`
  - `setcc`, `cmovcc`
  - `cdq`/`cqo`, `cwde`/`cdqe`, `syscall`, `endbr64`, `nop`, `int`, `int3`
- **Relative branch resolution** — all `jmp`, `Jcc`, and `call` targets
  are printed as absolute virtual addresses.
- **Section and address selection** — disassemble `.text` by default, or
  any named section, or start at an arbitrary virtual address.
- **Byte listing mode** (`-l`) that mirrors `objdump -d` layout.

---

## Usage

```
penguins-eng [options] <elf-file>

Options:
  -s <section>   Disassemble only the named section (default: .text)
  -a <address>   Start disassembly at a virtual address (hex, no 0x needed)
  -n <count>     Limit the number of instructions printed
  -l             Show raw bytes alongside each instruction
  -h, --help     Show this help
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Usage error, file not found, or not a valid x86-64 ELF |
| 2 | Reserved for future use (partial decode, malformed section) |

---

## Architecture

```
                 ┌────────────────────┐
   ELF file ───▶ │  ElfParser         │  header, sections, vaddr→offset
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │  Disassembler      │  prefix / opcode / ModRM / SIB
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │  Instruction       │  { address, bytes, mnemonic, ops }
                 └─────────┬──────────┘
                           │
                           ▼
                    src/main.cpp      formatting + CLI
```

- `src/elf_parser.{hpp,cpp}` — loads the file, validates the ELF64 magic /
  class / endianness / machine, parses section headers and names, and
  provides `vaddr_to_offset` / `read_at_vaddr`.
- `src/decoder_table.hpp` — shared types: `OpType`, `Operand`,
  `Instruction`, and the register-name tables.
- `src/disassembler.{hpp,cpp}` — the decoder. `decode_one` handles a
  single instruction; `disassemble_buffer` walks a byte range;
  `disassemble_section` runs over a named section.
- `src/main.cpp` — banner, argument parsing, output formatting.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a fuller walkthrough
of the decode flow.

---

## Status & limitations

This is a **linear-sweep** disassembler, not a recursive-descent one. That
means:

- Data embedded in `.text` (jump tables, alignment padding interpreted as
  code) is disassembled as if it were instructions. Once the decoder is
  desynchronized, subsequent instructions can be wrong until the next
  unambiguous boundary.
- Unimplemented opcodes print as `db 0xNN`, one byte per line, which is
  correct but noisy. Known gaps include SSE/AVX, `0xC6`/`0xC7` immediate
  moves, `0F 0F` (3DNow!), string ops (`movs`, `stos`, `lods`, `scas`,
  `cmps`), and x87.
- No symbol resolution. `call 0x40b0` shows the address, not the name.
- No relocation or PLT/GOT annotation.
- `0x66` operand-size override is not tracked; 16-bit forms render as
  32/64-bit.
- `0xF3` is only special-cased for `endbr64`.

See the [Beta warning](#pe-linux--penguins-engineering) at the top for the
full caveat list. Contributions that add opcode families, symbol lookup,
or a recursive-descent sweep are welcome.

---

## Verifying against objdump

For any range you disassemble, `objdump` is the ground truth:

```bash
objdump -d --start-address=0x1cd87 --stop-address=0x1cd98 /bin/ls
```

Mnemonic and operand text should match for every supported opcode. The
remaining differences are formatting (objdump uses tab alignment; PE Linux
uses fixed-width columns) and unimplemented opcodes (which objdump prints
as real mnemonics and PE Linux prints as `db 0xNN`).

---

## Roadmap

Tracking the path to v1.0. Nothing here is a promise; order may change.

- [ ] `0xC6` / `0xC7` — `mov r/m, imm8` / `mov r/m, imm32` (highest
      priority; very common, currently prints as `db`)
- [ ] `0xA4..0xA7`, `0xAA..0xAF` — `movs`, `cmps`, `stos`, `lods`, `scas`
- [ ] Symbol resolution via `.symtab` / `.dynsym`
- [ ] String-literal annotation for `lea rXX, [rip+...]`
- [ ] Recursive-descent mode from `e_entry` and symbols
- [ ] SSE / SSE2 scalar and packed moves
- [ ] x87 floating point
- [ ] 16-bit operand-size tracking for the `0x66` prefix
- [ ] Test suite with byte-level regression cases
- [ ] GitHub Actions CI on Ubuntu + Alpine

---

## Contributing

Contributions are welcome. The highest-impact changes are new opcodes and
fixes to existing ones — the decoder is small enough that a single well-
tested `case` can meaningfully expand coverage.

**Workflow:**

1. Fork the repository.
2. Create a branch: `git checkout -b feature/add-c7-immediate-mov`.
3. Add the opcode(s). Follow the existing `case` template in
   `src/disassembler.cpp`.
4. Test against `objdump` on a real binary (`/bin/ls`, `/usr/bin/bash`,
   or `/usr/bin/gcc` are good choices).
5. Commit with a clear message: `add 0xC7 mov r/m, imm32`.
6. Open a pull request describing what was added and how it was tested.

**Guidelines:**

- One logical change per pull request. Don't mix an opcode addition with a
  formatting tweak.
- Keep the code style consistent: 4-space indents, `std::ostringstream`
  for formatting, `format_rm` and `hex_imm` for operand rendering.
- If you add a new opcode family, update the "Status & limitations" and
  "Roadmap" sections of this README.
- Bug fixes are more valuable than new features right now. If you find a
  mismatch against objdump, please open an issue with the exact bytes,
  the address, and both outputs side by side.

**Reporting bugs:**

Open an issue with:

- The output of `penguins-eng --help`.
- The binary's hash (`sha256sum /bin/ls`).
- The exact command you ran.
- The PE Linux output and the corresponding `objdump` output for the same
  address range.
- The first line where they differ.

That last one is the whole bug. Everything before it is context.

---

## License

MIT — see [`LICENSE`](LICENSE).

PE Linux is not affiliated with Penguin Computing, Penguins Engineering
(the fictional entity in the banner), or any other organization. The name
is a pun.
