#include "elf_parser.hpp"
#include <fstream>
#include <cstring>
#include <stdexcept>

namespace penguins {

ElfParser::ElfParser(const std::string& path) : path_(path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        error_ = "Cannot open file: " + path;
        return;
    }
    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    f.seekg(0, std::ios::beg);
    data_.resize(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data_.data()), size);
    if (!f) {
        error_ = "Failed to read file: " + path;
        return;
    }
    valid_ = parse();
}

ElfParser::~ElfParser() = default;

bool ElfParser::parse() {
    if (data_.size() < sizeof(Elf64_Ehdr)) {
        error_ = "File too small for ELF header";
        return false;
    }
    std::memcpy(&ehdr_, data_.data(), sizeof(Elf64_Ehdr));

    if (std::memcmp(ehdr_.e_ident, "\x7f""ELF", 4) != 0) {
        error_ = "Not an ELF file";
        return false;
    }
    if (ehdr_.e_ident[4] != 2) { // ELFCLASS64
        error_ = "Only 64-bit ELF supported";
        return false;
    }
    if (ehdr_.e_ident[5] != 1) { // ELFDATA2LSB
        error_ = "Only little-endian ELF supported";
        return false;
    }
    if (ehdr_.e_machine != 0x3E) { // EM_X86_64
        error_ = "Only x86-64 architecture supported";
        return false;
    }

    // Section headers
    if (ehdr_.e_shoff + ehdr_.e_shnum * sizeof(Elf64_Shdr) > data_.size()) {
        error_ = "Section header table out of bounds";
        return false;
    }
    sections_.resize(ehdr_.e_shnum);
    std::memcpy(sections_.data(),
                data_.data() + ehdr_.e_shoff,
                ehdr_.e_shnum * sizeof(Elf64_Shdr));

    // Section name string table
    section_names_.resize(ehdr_.e_shnum);
    if (ehdr_.e_shstrndx < ehdr_.e_shnum) {
        const auto& shstrtab = sections_[ehdr_.e_shstrndx];
        for (size_t i = 0; i < sections_.size(); ++i) {
            section_names_[i] = read_cstr(shstrtab.sh_offset + sections_[i].sh_name);
        }
    }
    return true;
}

std::string ElfParser::read_cstr(size_t offset) const {
    if (offset >= data_.size()) return {};
    const char* p = reinterpret_cast<const char*>(data_.data() + offset);
    size_t max = data_.size() - offset;
    size_t len = strnlen(p, max);
    return std::string(p, len);
}

const std::string& ElfParser::section_name(uint32_t idx) const {
    static const std::string empty;
    if (idx >= section_names_.size()) return empty;
    return section_names_[idx];
}

const Elf64_Shdr* ElfParser::find_section(const std::string& name) const {
    for (size_t i = 0; i < sections_.size(); ++i) {
        if (section_names_[i] == name) return &sections_[i];
    }
    return nullptr;
}

bool ElfParser::vaddr_to_offset(uint64_t vaddr, uint64_t& offset) const {
    for (const auto& s : sections_) {
        if (s.sh_addr == 0) continue;
        if (vaddr >= s.sh_addr && vaddr < s.sh_addr + s.sh_size) {
            offset = s.sh_offset + (vaddr - s.sh_addr);
            return true;
        }
    }
    return false;
}

bool ElfParser::read_at_vaddr(uint64_t vaddr, size_t len, std::vector<uint8_t>& out) const {
    uint64_t off = 0;
    if (!vaddr_to_offset(vaddr, off)) return false;
    if (off + len > data_.size()) return false;
    out.assign(data_.begin() + off, data_.begin() + off + len);
    return true;
}

} // namespace penguins
