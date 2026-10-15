#include "elf_parser.hpp"
#include "disassembler.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <string>

using namespace penguins;

static void usage(const char* prog) {
    std::cerr << "Penguins Engineering - Linux x86-64 Disassembler\n"
              << "Usage: " << prog << " [options] <elf-file>\n\n"
              << "Options:\n"
              << "  -s <section>   Disassemble only the named section (e.g. .text)\n"
              << "  -a <address>   Start disassembly at virtual address (hex)\n"
              << "  -n <count>     Limit number of instructions\n"
              << "  -l             Show raw bytes\n"
              << "  -h, --help     Show this help\n";
}

static void print_instruction(const Instruction& ins, bool show_bytes) {
    std::printf("%016lx: ", ins.address);
    if (show_bytes) {
        for (int i = 0; i < 8; ++i) {
            if (i < ins.length) std::printf("%02x ", ins.bytes[i]);
            else                std::printf("   ");
        }
        std::printf("  ");
    }
    std::printf("%-8s %s\n", ins.mnemonic.c_str(), ins.op_str.c_str());
}

int main(int argc, char** argv) {
    std::string path;
    std::string section = ".text";
    uint64_t start_addr = 0;
    bool have_addr = false;
    size_t limit = 0;
    bool show_bytes = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else if (a == "-s" && i + 1 < argc) section = argv[++i];
        else if (a == "-a" && i + 1 < argc) { start_addr = std::stoull(argv[++i], nullptr, 16); have_addr = true; }
        else if (a == "-n" && i + 1 < argc) limit = std::stoull(argv[++i]);
        else if (a == "-l") show_bytes = true;
        else if (!a.empty() && a[0] != '-') path = a;
        else { std::cerr << "Unknown option: " << a << "\n"; usage(argv[0]); return 1; }
    }

    if (path.empty()) { usage(argv[0]); return 1; }

    std::printf("\x1b[1;36m");
    std::printf("  ___           _                _____         _            \n");
    std::printf(" | _ \\___ _ _  (_)__ _ _ _  ___  | ____|_  _ __(_)_ _  ___ _ _ \n");
    std::printf(" |  _/ -_) ' \\ | / _` | ' \\/ _ \\ |  _|| || / _` | ' \\/ -_) ' \\\n");
    std::printf(" |_| \\___|_||_|_|\\__, |_||_\\___/ |_____|\\_, \\__, |_||_\\___|_||_|\n");
    std::printf("                 |___/                  |__/  |_/             \n");
    std::printf("\x1b[0m\n");

    ElfParser elf(path);
    if (!elf.is_valid()) {
        std::cerr << "Error: " << elf.error() << "\n";
        return 1;
    }

    std::printf("File   : %s\n", path.c_str());
    std::printf("Type   : %s\n", elf.header().e_type == 2 ? "EXEC" :
                                  elf.header().e_type == 3 ? "DYN (PIE)" : "OTHER");
    std::printf("Entry  : 0x%lx\n", elf.header().e_entry);
    std::printf("Section: %s\n\n", section.c_str());

    std::vector<Instruction> insns;

    if (have_addr) {
        // Disassemble from a specific virtual address
        std::vector<uint8_t> buf;
        if (!elf.read_at_vaddr(start_addr, 4096, buf)) {
            std::cerr << "Error: cannot read at 0x" << std::hex << start_addr << "\n";
            return 1;
        }
        insns = Disassembler::disassemble_buffer(buf.data(), buf.size(), start_addr);
    } else {
        insns = Disassembler::disassemble_section(elf, section);
        if (insns.empty()) {
            std::cerr << "Error: section '" << section << "' not found or empty\n";
            return 1;
        }
    }

    size_t shown = 0;
    for (const auto& ins : insns) {
        print_instruction(ins, show_bytes);
        if (limit && ++shown >= limit) break;
    }

    return 0;
}
