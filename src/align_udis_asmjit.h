#ifndef REDMAGIC_ALIGN_UDIS_ASMJIT_H_
#define REDMAGIC_ALIGN_UDIS_ASMJIT_H_

#include <asmjit/asmjit.h>
#include <udis86.h>

#include "jit_internal.h"


/**
 * Attempt to align the instructions between udis86 and asmjit so that we can directly convert from a udis decompile to a asmjit instruction
 * this is helpful since we can use this to slightly modify one of the instructions
 */

namespace redmagic {

  class AlignedInstructions {
  public:
    AlignedInstructions(ud_t *disassm);

    struct operand_info {
      // UD_OP_*
      enum ud_type type;

      int8_t base_register;
      int8_t index_register;
      int8_t index_scale;
      int64_t offset;

      int8_t register_i;

      int64_t imm_value;

      mem_loc_t address;
    };

    inline size_t num_ops() { return number_operands; }
    inline operand_info* get_op(unsigned int i) {
      if(i >= number_operands)
        return nullptr;
      return &operands[i];
    }

    inline enum ud_mnemonic_code get_ud_mnem() { return ud_mnem; }
    inline enum asmjit::X86InstId get_asm_mnem() { return get_asm_mnem(ud_mnem); }
    static enum asmjit::X86InstId get_asm_mnem(enum ud_mnemonic_code mnem);

    const asmjit::Operand get_asm_op(unsigned int i);

    uint64_t registers_used();

    // replace all references to one register with another
    void ReplaceReigster(int from, int to);

    void Emit(asmjit::Assembler *assem);

  private:
    enum ud_mnemonic_code ud_mnem;
    int number_operands;
    operand_info operands[3];
    mem_loc_t pc;
    size_t len;

    void findAlignedAsmjit();
  };

  static auto& get_asm_register_from_sys(int id) {
    // take the sys struct register id and convert it to asmjit
    using namespace asmjit::x86;
    switch(id) {
    case R15: return r15;
    case R14: return r14;
    case R13: return r13;
    case R12: return r12;
    case RBP: return rbp;
    case RBX: return rbx;
    case R11: return r11;
    case R10: return r10;
    case R9:  return r9;
    case R8:  return r8;
    case RAX: return rax;
    case RCX: return rcx;
    case RDX: return rdx;
    case RSI: return rsi;
    case RDI: return rdi;
      //case RIP: return rip;
      //case CS:  return cs;
      // case RSP: return rsp;
      // case DS:  return ds;
      // case ES:  return es;
      // case FS:  return fs;
      // case GS:  return gs;
    }
    assert(0);
  }

  static int get_sys_register_from_asm(asmjit::X86GpReg& reg) {
    using namespace asmjit::x86;
    if(reg == r15) return R15;
    if(reg == r14) return R14;
    if(reg == r13) return R13;
    if(reg == r12) return R12;
    if(reg == rbp) return RBP;
    if(reg == rbx) return RBX;
    if(reg == r11) return R11;
    if(reg == r10) return R10;
    if(reg == r9 ) return R9;
    if(reg == r8 ) return R8;
    if(reg == rax) return RAX;
    if(reg == rcx) return RCX;
    if(reg == rdx) return RDX;
    if(reg == rsi) return RSI;
    if(reg == rdi) return RDI;

    assert(0);
  }


}


#endif // REDMAGIC_ALIGN_UDIS_ASMJIT_H_
