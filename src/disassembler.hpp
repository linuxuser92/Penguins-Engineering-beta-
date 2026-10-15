#pragma once
#include "decoder_table.hpp"
#include "elf_parser.hpp"
#include <vector>
#include <string>
#include <functional>

namespace penguins {

class Disassembler {
public:
    // Decode exactly one instruction starting at `data + pos`, with given virtual address
    // Returns number of bytes consumed (0 = unknown/failed).
    static size_t decode_one(const uint8_t* data, size_t max_len,
                             uint64_t vaddr, Instruction& out);

    // Disassemble a raw buffer
    static std::vector<Instruction> disassemble_buffer(const uint8_t* data, size_t len,
                                                       uint64_t vaddr);

    // Disassemble a whole section by name
    static std::vector<Instruction> disassemble_section(const ElfParser& elf,
                                                        const std::string& section);
};

} // namespace penguins
