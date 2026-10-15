#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace penguins {

// ELF64 structures (subset)
struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} __attribute__((packed));

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} __attribute__((packed));

struct Elf64_Rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} __attribute__((packed));

class ElfParser {
public:
    explicit ElfParser(const std::string& path);
    ~ElfParser();

    bool is_valid() const { return valid_; }
    const std::string& error() const { return error_; }

    // Accessors
    const Elf64_Ehdr& header() const { return ehdr_; }
    const std::vector<uint8_t>& raw() const { return data_; }
    const std::vector<Elf64_Shdr>& sections() const { return sections_; }
    const std::string& section_name(uint32_t idx) const;

    // Find a section by name (returns nullptr if not found)
    const Elf64_Shdr* find_section(const std::string& name) const;

    // Read bytes at virtual address
    bool read_at_vaddr(uint64_t vaddr, size_t len, std::vector<uint8_t>& out) const;
    bool vaddr_to_offset(uint64_t vaddr, uint64_t& offset) const;

private:
    bool parse();
    std::string read_cstr(size_t offset) const;

    std::string path_;
    std::vector<uint8_t> data_;
    Elf64_Ehdr ehdr_{};
    std::vector<Elf64_Shdr> sections_;
    std::vector<std::string> section_names_;
    std::string error_;
    bool valid_ = false;
};

} // namespace penguins
