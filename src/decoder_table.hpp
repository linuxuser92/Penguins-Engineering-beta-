#pragma once
#include <cstdint>
#include <string>
#include <array>

namespace penguins {

// Operand types for our small x86-64 decoder
enum class OpType : uint8_t {
    None,
    Reg8, Reg16, Reg32, Reg64,
    Imm8, Imm16, Imm32, Imm64,
    Rel8, Rel32,
    Rm8, Rm16, Rm32, Rm64,    // ModRM reg/mem
    M,                         // Memory operand
};

struct Operand {
    OpType type = OpType::None;
    int size = 0;
    int reg = -1;         // register index if direct register
    int64_t imm = 0;
    bool is_mem = false;  // ModRM produced memory
    // Memory details
    int base = -1;
    int index = -1;
    int scale = 1;
    int64_t disp = 0;
    bool rip_rel = false;
};

struct Instruction {
    uint64_t address = 0;
    uint8_t length = 0;
    std::string mnemonic;
    std::string op_str;
    uint8_t bytes[16]{};
};

// Register name tables
extern const char* REG8[16];
extern const char* REG16[16];
extern const char* REG32[16];
extern const char* REG64[16];

} // namespace penguins
