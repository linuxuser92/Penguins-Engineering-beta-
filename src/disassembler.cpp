#include "disassembler.hpp"
#include <cstdio>
#include <cstring>
#include <sstream>

namespace penguins {

// ============================================================
//  Register name tables
// ============================================================
const char* REG8[16]  = {"al","cl","dl","bl","spl","bpl","sil","dil",
                         "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
const char* REG16[16] = {"ax","cx","dx","bx","sp","bp","si","di",
                         "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
const char* REG32[16] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                         "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
const char* REG64[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                         "r8","r9","r10","r11","r12","r13","r14","r15"};

// ============================================================
//  Helpers
// ============================================================
static const char* reg_name(int size, int idx) {
    switch (size) {
        case 1: return REG8[idx & 15];
        case 2: return REG16[idx & 15];
        case 4: return REG32[idx & 15];
        case 8: return REG64[idx & 15];
        default: return "?";
    }
}

static int acc_reg_index() { return 0; }

static std::string hex_imm(int64_t imm, int size) {
    std::ostringstream os;
    if (size == 1) {
        os << "0x" << std::hex << (uint64_t)(uint8_t)imm;
    } else if (size == 2) {
        os << "0x" << std::hex << (uint64_t)(uint16_t)imm;
    } else if (size == 4) {
        os << "0x" << std::hex << (uint64_t)(uint32_t)imm;
    } else {
        os << "0x" << std::hex << (uint64_t)imm;
    }
    return os.str();
}

// ------------------------------------------------------------
//  ModRM + SIB decoding
// ------------------------------------------------------------
static int decode_modrm(const uint8_t* p, size_t max, size_t pos,
                        bool /*rex_w*/, int rex_r, int rex_x, int rex_b,
                        int operand_size,
                        Operand& rm_out, int& reg_out, bool& is_mem) {
    if (pos >= max) return -1;
    uint8_t modrm = p[pos++];
    int mod = (modrm >> 6) & 3;
    int reg = ((modrm >> 3) & 7) | (rex_r << 3);
    int rm  = (modrm & 7) | (rex_b << 3);
    reg_out = reg;
    is_mem  = false;

    Operand op;
    op.is_mem = false;

    if (mod == 3) {
        op.type = OpType::Rm64;
        op.size = operand_size;
        op.reg  = rm;
        rm_out  = op;
        return (int)pos;
    }

    is_mem = true;
    op.is_mem = true;
    op.size   = operand_size;
    int base = -1, index = -1, scale = 1;
    int64_t disp = 0;
    bool rip_rel = false;

    if (rm == 4) {
        if (pos >= max) return -1;
        uint8_t sib = p[pos++];
        scale = 1 << ((sib >> 6) & 3);
        index = ((sib >> 3) & 7) | (rex_x << 3);
        base  = (sib & 7)        | (rex_b << 3);
        if (index == 4) index = -1;
        if ((sib & 7) == 5 && mod == 0) {
            if (pos + 4 > max) return -1;
            int32_t d; std::memcpy(&d, p + pos, 4); pos += 4;
            disp = d;
            base = -1;
        }
    } else if (rm == 5 && mod == 0) {
        if (pos + 4 > max) return -1;
        int32_t d; std::memcpy(&d, p + pos, 4); pos += 4;
        disp = d;
        rip_rel = true;
        base = -1;
    } else {
        base = rm;
    }

    if (mod == 1) {
        if (pos >= max) return -1;
        disp += (int8_t)p[pos++];
    } else if (mod == 2) {
        if (pos + 4 > max) return -1;
        int32_t d; std::memcpy(&d, p + pos, 4); pos += 4;
        disp += d;
    }

    op.base    = base;
    op.index   = index;
    op.scale   = scale;
    op.disp    = disp;
    op.rip_rel = rip_rel;
    op.reg     = -1;
    rm_out     = op;
    return (int)pos;
}

static std::string format_rm(const Operand& op, int operand_size) {
    std::ostringstream os;
    if (!op.is_mem) {
        return reg_name(operand_size, op.reg);
    }
    os << "[";
    bool first = true;
    if (op.rip_rel) {
        os << "rip";
        first = false;
        if (op.disp) {
            os << (op.disp < 0 ? "-" : "+")
               << "0x" << std::hex << (uint64_t)(op.disp < 0 ? -op.disp : op.disp);
        }
        os << "]";
        return os.str();
    }
    if (op.base >= 0) {
        os << reg_name(8, op.base);
        first = false;
    }
    if (op.index >= 0) {
        if (!first) os << "+";
        os << reg_name(8, op.index);
        if (op.scale != 1) os << "*" << op.scale;
        first = false;
    }
    if (op.disp != 0 || first) {
        if (!first) os << (op.disp < 0 ? "-" : "+");
        else if (op.disp < 0) os << "-";
        uint64_t d = op.disp < 0 ? (uint64_t)(-op.disp) : (uint64_t)op.disp;
        os << "0x" << std::hex << d;
    }
    os << "]";
    return os.str();
}

// ============================================================
//  Main decoder
// ============================================================
size_t Disassembler::decode_one(const uint8_t* data, size_t max_len,
                                uint64_t vaddr, Instruction& out) {
    if (max_len == 0) return 0;

    size_t pos = 0;
    bool rex_w = false;
    int rex_r = 0, rex_x = 0, rex_b = 0;

    // ---- Prefixes (legacy + REX) ----
    while (pos < max_len) {
        uint8_t b = data[pos];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {
            pos++;
        } else if (b >= 0x40 && b <= 0x4F) {
            rex_w = (b >> 3) & 1;
            rex_r = (b >> 2) & 1;
            rex_x = (b >> 1) & 1;
            rex_b = b & 1;
            pos++;
        } else {
            break;
        }
    }

    if (pos >= max_len) return 0;
    uint8_t op = data[pos++];

    int operand_size = rex_w ? 8 : 4;
    out.mnemonic.clear();
    out.op_str.clear();
    Operand rm, reg;
    int reg_idx = -1;
    bool is_mem = false;

    // ==========================================================
    //  Two-byte opcodes (0F xx)
    // ==========================================================
    if (op == 0x0F) {
        if (pos >= max_len) return 0;
        uint8_t op2 = data[pos++];
        switch (op2) {
            case 0x05:  out.mnemonic = "syscall"; break;
            case 0x0B:  out.mnemonic = "ud2"; break;

            // ---- 0F 1E: endbr64 / nop r/m ----
            case 0x1E: {
                if (pos < max_len && (data[pos] & 0xF8) == 0xFA) {
                    out.mnemonic = "endbr64";
                    pos++;
                } else {
                    out.mnemonic = "nop";
                    int r = decode_modrm(data, max_len, pos,
                                         rex_w, rex_r, rex_x, rex_b,
                                         operand_size, rm, reg_idx, is_mem);
                    if (r < 0) return 0;
                    pos = (size_t)r;
                }
                break;
            }

            case 0x1F: {
                out.mnemonic = "nop";
                if (pos < max_len) {
                    int r = decode_modrm(data, max_len, pos,
                                         rex_w, rex_r, rex_x, rex_b,
                                         operand_size, rm, reg_idx, is_mem);
                    if (r < 0) return 0;
                    pos = (size_t)r;
                }
                break;
            }

            case 0xAF: {
                out.mnemonic = "imul";
                int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                     operand_size, rm, reg_idx, is_mem);
                if (r < 0) return 0;
                pos = (size_t)r;
                std::ostringstream os;
                os << reg_name(operand_size, reg_idx) << ", "
                   << format_rm(rm, operand_size);
                out.op_str = os.str();
                break;
            }
            case 0xB6: case 0xB7: case 0xBE: case 0xBF: {
                bool sx = (op2 >= 0xBE);
                int srcsz = (op2 & 1) ? 2 : 1;
                out.mnemonic = sx ? "movsx" : "movzx";
                int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                     srcsz, rm, reg_idx, is_mem);
                if (r < 0) return 0;
                pos = (size_t)r;
                std::ostringstream os;
                os << reg_name(operand_size, reg_idx) << ", "
                   << format_rm(rm, srcsz);
                out.op_str = os.str();
                break;
            }

            // ==========================================================
            //  Jcc rel32  (0F 80 .. 0F 8F)   ← includes je/jne = 84/85
            // ==========================================================
            case 0x80: case 0x81: case 0x82: case 0x83:
            case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B:
            case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
                static const char* cc[] = {
                    "jo","jno","jb","jae","je","jne","jbe","ja",
                    "js","jns","jp","jnp","jl","jge","jle","jg"
                };
                out.mnemonic = cc[op2 - 0x80];
                if (pos + 4 > max_len) return 0;
                int32_t rel;
                std::memcpy(&rel, data + pos, 4);
                pos += 4;
                uint64_t target = vaddr + pos + rel;
                std::ostringstream os;
                os << "0x" << std::hex << target;
                out.op_str = os.str();
                break;
            }

            // ---- 0F 90..0F 9F : setcc r/m8 ----
            case 0x90: case 0x91: case 0x92: case 0x93:
            case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99: case 0x9A: case 0x9B:
            case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
                static const char* setcc[] = {
                    "seto","setno","setb","setae","sete","setne","setbe","seta",
                    "sets","setns","setp","setnp","setl","setge","setle","setg"
                };
                out.mnemonic = setcc[op2 - 0x90];
                int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                     1, rm, reg_idx, is_mem);
                if (r < 0) return 0;
                pos = (size_t)r;
                out.op_str = format_rm(rm, 1);
                break;
            }

            // ---- 0F 40..0F 4F : cmovcc r, r/m ----
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
                static const char* cmov[] = {
                    "cmovo","cmovno","cmovb","cmovae","cmove","cmovne","cmovbe","cmova",
                    "cmovs","cmovns","cmovp","cmovnp","cmovl","cmovge","cmovle","cmovg"
                };
                out.mnemonic = cmov[op2 - 0x40];
                int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                     operand_size, rm, reg_idx, is_mem);
                if (r < 0) return 0;
                pos = (size_t)r;
                std::ostringstream os;
                os << reg_name(operand_size, reg_idx) << ", "
                   << format_rm(rm, operand_size);
                out.op_str = os.str();
                break;
            }

            default:
                out.mnemonic = "db";
                {
                    std::ostringstream os;
                    os << "0x0f, 0x" << std::hex << (int)op2;
                    out.op_str = os.str();
                }
                out.length  = (uint8_t)pos;
                out.address = vaddr;
                std::memcpy(out.bytes, data, pos);
                return pos;
        }
    }
    // ==========================================================
    //  One-byte opcodes
    // ==========================================================
    else {
        switch (op) {

        // ---------------- push/pop reg ----------------
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: {
            out.mnemonic = "push";
            int r = (op - 0x50) | (rex_b << 3);
            out.op_str = reg_name(8, r);
            break;
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            out.mnemonic = "pop";
            int r = (op - 0x58) | (rex_b << 3);
            out.op_str = reg_name(8, r);
            break;
        }

        // ---------------- mov r, imm ----------------
        case 0xB0: case 0xB1: case 0xB2: case 0xB3:
        case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
            out.mnemonic = "mov";
            int r = (op - 0xB0) | (rex_b << 3);
            if (pos >= max_len) return 0;
            int8_t imm = (int8_t)data[pos++];
            std::ostringstream os;
            os << reg_name(1, r) << ", " << hex_imm(imm, 1);
            out.op_str = os.str();
            break;
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            out.mnemonic = "mov";
            int r = (op - 0xB8) | (rex_b << 3);
            int imm_size = rex_w ? 8 : 4;
            if (pos + imm_size > max_len) return 0;
            int64_t imm = 0;
            std::memcpy(&imm, data + pos, imm_size);
            pos += imm_size;
            std::ostringstream os;
            os << reg_name(imm_size, r) << ", " << hex_imm(imm, imm_size);
            out.op_str = os.str();
            break;
        }

        // ---------------- mov r/m, r and r, r/m ----------------
        case 0x88: case 0x89: {
            out.mnemonic = "mov";
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            int sz = (op == 0x88) ? 1 : operand_size;
            std::ostringstream os;
            os << format_rm(rm, sz) << ", " << reg_name(sz, reg_idx);
            out.op_str = os.str();
            break;
        }
        case 0x8A: case 0x8B: {
            out.mnemonic = "mov";
            int sz = (op == 0x8A) ? 1 : operand_size;
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 sz, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            std::ostringstream os;
            os << reg_name(sz, reg_idx) << ", " << format_rm(rm, sz);
            out.op_str = os.str();
            break;
        }

        // ---------------- lea ----------------
        case 0x8D: {
            out.mnemonic = "lea";
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            std::ostringstream os;
            os << reg_name(operand_size, reg_idx) << ", "
               << format_rm(rm, operand_size);
            out.op_str = os.str();
            break;
        }

        // ==========================================================
        //  Accumulator, imm8  (short form:  <op> al, imm8)
        // ==========================================================
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C: {
            static const char* mn8[] = {
                "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"
            };
            out.mnemonic = mn8[(op - 0x04) >> 3];
            if (pos >= max_len) return 0;
            int8_t imm = (int8_t)data[pos++];
            std::ostringstream os;
            os << "al, " << hex_imm(imm, 1);
            out.op_str = os.str();
            break;
        }

        // ==========================================================
        //  Accumulator, imm32  (short form:  <op> eax|rax, imm32)
        // ==========================================================
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D: {
            static const char* mn32[] = {
                "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"
            };
            out.mnemonic = mn32[(op - 0x05) >> 3];

            int dest_size = rex_w ? 8 : 4;
            if (pos + 4 > max_len) return 0;
            int32_t imm32 = 0;
            std::memcpy(&imm32, data + pos, 4);
            pos += 4;
            int64_t imm = rex_w ? (int64_t)imm32 : (int64_t)(uint32_t)imm32;

            std::ostringstream os;
            os << reg_name(dest_size, acc_reg_index()) << ", "
               << hex_imm(imm, dest_size);
            out.op_str = os.str();
            break;
        }

        // ---------------- r/m, r  (add/sub/xor/cmp) ----------------
        case 0x01: case 0x29: case 0x31: case 0x39: {
            const char* mn = (op == 0x01) ? "add"
                           : (op == 0x29) ? "sub"
                           : (op == 0x31) ? "xor"
                                          : "cmp";
            out.mnemonic = mn;
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            std::ostringstream os;
            os << format_rm(rm, operand_size) << ", "
               << reg_name(operand_size, reg_idx);
            out.op_str = os.str();
            break;
        }
        case 0x03: case 0x2B: case 0x33: case 0x3B: {
            const char* mn = (op == 0x03) ? "add"
                           : (op == 0x2B) ? "sub"
                           : (op == 0x33) ? "xor"
                                          : "cmp";
            out.mnemonic = mn;
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            std::ostringstream os;
            os << reg_name(operand_size, reg_idx) << ", "
               << format_rm(rm, operand_size);
            out.op_str = os.str();
            break;
        }
        case 0x00: case 0x08: case 0x10: case 0x18:
        case 0x20: case 0x28: case 0x30: case 0x38: {
            static const char* mn8[] = {
                "add","or","adc","sbb","and","sub","xor","cmp"
            };
            out.mnemonic = mn8[(op - 0x00) >> 3];
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 1, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            std::ostringstream os;
            os << format_rm(rm, 1) << ", " << reg_name(1, reg_idx);
            out.op_str = os.str();
            break;
        }
        case 0x02: case 0x0A: case 0x12: case 0x1A:
        case 0x22: case 0x2A: case 0x32: case 0x3A: {
            static const char* mn8[] = {
                "add","or","adc","sbb","and","sub","xor","cmp"
            };
            out.mnemonic = mn8[(op - 0x02) >> 3];
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 1, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            std::ostringstream os;
            os << reg_name(1, reg_idx) << ", " << format_rm(rm, 1);
            out.op_str = os.str();
            break;
        }

        // ==========================================================
        //  Group 1: imm to r/m  (imm32 sign-extended for 0x81)
        // ==========================================================
        case 0x80: case 0x81: case 0x83: {
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            static const char* mn[] = {
                "add","or","adc","sbb","and","sub","xor","cmp"
            };
            out.mnemonic = mn[reg_idx & 7];

            int64_t imm = 0;
            if (op == 0x80) {
                if (pos >= max_len) return 0;
                imm = (int8_t)data[pos++];
            } else if (op == 0x81) {
                if (pos + 4 > max_len) return 0;
                int32_t imm32 = 0;
                std::memcpy(&imm32, data + pos, 4);
                pos += 4;
                imm = (int64_t)imm32;
            } else { // 0x83
                if (pos >= max_len) return 0;
                imm = (int8_t)data[pos++];
            }

            std::ostringstream os;
            os << format_rm(rm, operand_size) << ", "
               << hex_imm(imm, operand_size);
            out.op_str = os.str();
            break;
        }

        // ==========================================================
        //  test r/m, r   (one-byte 0x84 / 0x85)
        //  This is the block you pasted. It belongs here, NOT in 0F.
        // ==========================================================
        case 0x84: case 0x85: {
            out.mnemonic = "test";
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            std::ostringstream os;
            os << format_rm(rm, operand_size) << ", "
               << reg_name(operand_size, reg_idx);
            out.op_str = os.str();
            break;
        }

        // ---------------- xchg r/m, r ----------------
        case 0x86: case 0x87: {
            out.mnemonic = "xchg";
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            int sz = (op == 0x86) ? 1 : operand_size;
            std::ostringstream os;
            os << format_rm(rm, sz) << ", " << reg_name(sz, reg_idx);
            out.op_str = os.str();
            break;
        }

        // ---------------- test al|ax|eax|rax, imm ----------------
        case 0xA8: {
            out.mnemonic = "test";
            if (pos >= max_len) return 0;
            int8_t imm = (int8_t)data[pos++];
            std::ostringstream os;
            os << "al, " << hex_imm(imm, 1);
            out.op_str = os.str();
            break;
        }
        case 0xA9: {
            out.mnemonic = "test";
            int dest_size = rex_w ? 8 : 4;
            if (pos + 4 > max_len) return 0;
            int32_t imm32 = 0;
            std::memcpy(&imm32, data + pos, 4);
            pos += 4;
            int64_t imm = rex_w ? (int64_t)imm32 : (int64_t)(uint32_t)imm32;
            std::ostringstream os;
            os << reg_name(dest_size, acc_reg_index()) << ", "
               << hex_imm(imm, dest_size);
            out.op_str = os.str();
            break;
        }

        // ---------------- simple / no-operand ----------------
        case 0x90: out.mnemonic = "nop";   break;
        case 0x98: out.mnemonic = rex_w ? "cdqe" : "cwde"; break;
        case 0x99: out.mnemonic = rex_w ? "cqo"  : "cdq";  break;
        case 0xC3: out.mnemonic = "ret";   break;
        case 0xC9: out.mnemonic = "leave"; break;
        case 0xCC: out.mnemonic = "int3";  break;
        case 0xCD: {
            out.mnemonic = "int";
            if (pos >= max_len) return 0;
            std::ostringstream os;
            os << "0x" << std::hex << (int)data[pos++];
            out.op_str = os.str();
            break;
        }

        // ---------------- push imm ----------------
        case 0x68: {
            out.mnemonic = "push";
            if (pos + 4 > max_len) return 0;
            int32_t imm; std::memcpy(&imm, data + pos, 4); pos += 4;
            std::ostringstream os;
            os << hex_imm((int64_t)imm, 4);
            out.op_str = os.str();
            break;
        }
        case 0x6A: {
            out.mnemonic = "push";
            if (pos >= max_len) return 0;
            int8_t imm = (int8_t)data[pos++];
            std::ostringstream os;
            os << hex_imm(imm, 1);
            out.op_str = os.str();
            break;
        }

        // ---------------- Jcc rel8 ----------------
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
        case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            static const char* cc[] = {
                "jo","jno","jb","jae","je","jne","jbe","ja",
                "js","jns","jp","jnp","jl","jge","jle","jg"
            };
            out.mnemonic = cc[op - 0x70];
            if (pos >= max_len) return 0;
            int8_t rel = (int8_t)data[pos++];
            uint64_t target = vaddr + pos + rel;
            std::ostringstream os;
            os << "0x" << std::hex << target;
            out.op_str = os.str();
            break;
        }

        // ---------------- jmp rel8/rel32, call rel32 ----------------
        case 0xEB: {
            out.mnemonic = "jmp";
            if (pos >= max_len) return 0;
            int8_t rel = (int8_t)data[pos++];
            uint64_t target = vaddr + pos + rel;
            std::ostringstream os;
            os << "0x" << std::hex << target;
            out.op_str = os.str();
            break;
        }
        case 0xE9: {
            out.mnemonic = "jmp";
            if (pos + 4 > max_len) return 0;
            int32_t rel; std::memcpy(&rel, data + pos, 4); pos += 4;
            uint64_t target = vaddr + pos + rel;
            std::ostringstream os;
            os << "0x" << std::hex << target;
            out.op_str = os.str();
            break;
        }
        case 0xE8: {
            out.mnemonic = "call";
            if (pos + 4 > max_len) return 0;
            int32_t rel; std::memcpy(&rel, data + pos, 4); pos += 4;
            uint64_t target = vaddr + pos + rel;
            std::ostringstream os;
            os << "0x" << std::hex << target;
            out.op_str = os.str();
            break;
        }

        // ---------------- group 3: f6 / f7 ----------------
        case 0xF6: case 0xF7: {
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            static const char* g3[] = {
                "test","test","not","neg","mul","imul","div","idiv"
            };
            out.mnemonic = g3[reg_idx & 7];
            std::ostringstream os;
            os << format_rm(rm, operand_size);
            if ((reg_idx & 7) <= 1) {
                int imm_size = (op == 0xF6) ? 1 : 4;
                if (pos + imm_size > max_len) return 0;
                int64_t imm = 0;
                if (imm_size == 1) {
                    imm = (int8_t)data[pos++];
                } else {
                    int32_t imm32 = 0;
                    std::memcpy(&imm32, data + pos, 4);
                    pos += 4;
                    imm = (int64_t)imm32;
                }
                os << ", " << hex_imm(imm, operand_size);
            }
            out.op_str = os.str();
            break;
        }

        // ---------------- group 4/5: inc/dec/call/jmp/push (ff) ----------------
        case 0xFE: case 0xFF: {
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            static const char* mn[] = {
                "inc","dec","call","callf","jmp","jmpf","push","?"
            };
            out.mnemonic = mn[reg_idx & 7];
            std::ostringstream os;
            os << format_rm(rm, operand_size);
            out.op_str = os.str();
            break;
        }

        // ---------------- shifts ----------------
        case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
            int r = decode_modrm(data, max_len, pos, rex_w, rex_r, rex_x, rex_b,
                                 operand_size, rm, reg_idx, is_mem);
            if (r < 0) return 0;
            pos = (size_t)r;
            static const char* sh[] = {
                "rol","ror","rcl","rcr","shl","shr","sal","sar"
            };
            out.mnemonic = sh[reg_idx & 7];
            std::ostringstream os;
            os << format_rm(rm, operand_size);
            if (op == 0xC0 || op == 0xC1) {
                if (pos >= max_len) return 0;
                os << ", 0x" << std::hex << (int)data[pos++];
            } else if (op == 0xD2 || op == 0xD3) {
                os << ", cl";
            }
            out.op_str = os.str();
            break;
        }

        // ---------------- fallback ----------------
        default:
            out.mnemonic = "db";
            {
                std::ostringstream os;
                os << "0x" << std::hex << (int)op;
                out.op_str = os.str();
            }
            break;
        }
    }

    out.length  = (uint8_t)pos;
    out.address = vaddr;
    std::memcpy(out.bytes, data, pos);
    return pos;
}

// ============================================================
//  Bulk helpers
// ============================================================
std::vector<Instruction> Disassembler::disassemble_buffer(const uint8_t* data, size_t len,
                                                          uint64_t vaddr) {
    std::vector<Instruction> result;
    size_t pos = 0;
    while (pos < len) {
        Instruction ins;
        size_t consumed = decode_one(data + pos, len - pos, vaddr + pos, ins);
        if (consumed == 0) {
            ins.address  = vaddr + pos;
            ins.length   = 1;
            ins.mnemonic = "db";
            std::ostringstream os;
            os << "0x" << std::hex << (int)data[pos];
            ins.op_str   = os.str();
            ins.bytes[0] = data[pos];
            consumed = 1;
        }
        result.push_back(ins);
        pos += consumed;
    }
    return result;
}

std::vector<Instruction> Disassembler::disassemble_section(const ElfParser& elf,
                                                           const std::string& section) {
    const Elf64_Shdr* sh = elf.find_section(section);
    if (!sh) return {};
    if (sh->sh_offset + sh->sh_size > elf.raw().size()) return {};
    return disassemble_buffer(elf.raw().data() + sh->sh_offset,
                              (size_t)sh->sh_size,
                              sh->sh_addr);
}

} // namespace penguins
