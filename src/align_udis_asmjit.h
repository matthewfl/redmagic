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

  struct register_info {
    int8_t index;
    int8_t size;
    ud_type ud_reg_type;
  };

  class AlignedInstructions {
  public:
    AlignedInstructions(ud_t *disassm);

    struct operand_info {
      // UD_OP_*
      enum ud_type type;

      register_info base_register = {-1};
      register_info index_register = {-1};
      int8_t index_scale;
      int64_t offset;

      register_info register_i = {-1};

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

  static int ud_register_to_size(ud_type t) {
    switch(t) {
    case UD_R_R15B:
    case UD_R_R14B:
    case UD_R_R13B:
    case UD_R_R12B:
    case UD_R_CH:
    case UD_R_BL:
    case UD_R_R11B:
    case UD_R_R10B:
    case UD_R_R9B:
    case UD_R_R8B:
    case UD_R_AL:
    case UD_R_CL:
    case UD_R_DL:
    case UD_R_DH:
    case UD_R_BH:
    case UD_R_AH:
      return 8;

    case UD_R_R15W:
    case UD_R_R14W:
    case UD_R_R13W:
    case UD_R_R12W:
    case UD_R_BP:
    case UD_R_BX:
    case UD_R_R11W:
    case UD_R_R10W:
    case UD_R_R9W:
    case UD_R_R8W:
    case UD_R_AX:
    case UD_R_CX:
    case UD_R_DX:
    case UD_R_SI:
    case UD_R_DI:
    case UD_R_SP:
      return 16;

    case UD_R_R15D:
    case UD_R_R14D:
    case UD_R_R13D:
    case UD_R_R12D:
    case UD_R_EBP:
    case UD_R_EBX:
    case UD_R_R11D:
    case UD_R_R10D:
    case UD_R_R9D:
    case UD_R_R8D:
    case UD_R_EAX:
    case UD_R_ECX:
    case UD_R_EDX:
    case UD_R_EDI:
    case UD_R_ESI:
    case UD_R_ESP:
    case UD_R_DS:
    case UD_R_ES:
    case UD_R_FS:
    case UD_R_GS:
    case UD_R_CS:
      return 32;

    case UD_R_R15:
    case UD_R_R14:
    case UD_R_R13:
    case UD_R_R12:
    case UD_R_RBP:
    case UD_R_RBX:
    case UD_R_R11:
    case UD_R_R10:
    case UD_R_R9:
    case UD_R_R8:
    case UD_R_RAX:
    case UD_R_RCX:
    case UD_R_RDX:
    case UD_R_RSI:
    case UD_R_RDI:
    case UD_R_RIP:
    case UD_R_RSP:
      return 64;

    default:
      return -1;

    }
  }

  // convert a register from udis to sys/reg.h
  static int ud_register_to_sys(ud_type t) {
    switch(t) {
    case UD_R_R15B:
    case UD_R_R15W:
    case UD_R_R15D:
    case UD_R_R15:
      return R15;
    case UD_R_R14B:
    case UD_R_R14W:
    case UD_R_R14D:
    case UD_R_R14:
      return R14;
    case UD_R_R13B:
    case UD_R_R13W:
    case UD_R_R13D:
    case UD_R_R13:
      return R13;
    case UD_R_R12B:
    case UD_R_R12W:
    case UD_R_R12D:
    case UD_R_R12:
      return R12;
      //case UD_R_CH: // ??
    case UD_R_BP:
    case UD_R_EBP:
    case UD_R_RBP:
      return RBP;
    case UD_R_BL:
    case UD_R_BX:
    case UD_R_EBX:
    case UD_R_RBX:
      return RBX;
    case UD_R_R11B:
    case UD_R_R11W:
    case UD_R_R11D:
    case UD_R_R11:
      return R11;
    case UD_R_R10B:
    case UD_R_R10W:
    case UD_R_R10D:
    case UD_R_R10:
      return R10;
    case UD_R_R9B:
    case UD_R_R9W:
    case UD_R_R9D:
    case UD_R_R9:
      return R9;
    case UD_R_R8B:
    case UD_R_R8W:
    case UD_R_R8D:
    case UD_R_R8:
      return R8;
    case UD_R_AL:
    case UD_R_AH:
    case UD_R_AX:
    case UD_R_EAX:
    case UD_R_RAX:
      return RAX;
    case UD_R_CL:
    case UD_R_CH:
    case UD_R_CX:
    case UD_R_ECX:
    case UD_R_RCX:
      return RCX;
    case UD_R_DL:
    case UD_R_DH:
    case UD_R_DX:
    case UD_R_EDX:
    case UD_R_RDX:
      return RDX;
      //case UD_R_DH:
    case UD_R_SI:
    case UD_R_ESI:
    case UD_R_RSI:
      return RSI;
      //case UD_R_BH:
    case UD_R_DI:
    case UD_R_EDI:
    case UD_R_RDI:
      return RDI;
      // orig rax
    case UD_R_RIP:
      // instrunction pointer??
      return RIP;
    case UD_R_CS:
      return CS;
      // eflags not directly accessable, use pushf and popf
      //case UD_R_AH:
    case UD_R_SP:
    case UD_R_ESP:
    case UD_R_RSP:
      return RSP;
      // fsbase, gsbase
    case UD_R_DS:
      return DS;
    case UD_R_ES:
      return ES;
    case UD_R_FS:
      return FS;
    case UD_R_GS:
      return GS;
    default:
      return -1;
    }
  }

  static register_info ud_register_to_rinfo(ud_type t) {
    register_info r;
    r.index = ud_register_to_sys(t);
    r.size = ud_register_to_size(t);
    r.ud_reg_type = t;
    return r;
  }

  static auto& get_asm_register_from_rinfo(register_info r) {
    // take the sys struct register id and convert it to asmjit
    using namespace asmjit::x86;
    switch(r.size) {
    case 64:
      switch(r.index) {
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
    case 32:
      switch(r.index) {
      case R15: return r15d;
      case R14: return r14d;
      case R13: return r13d;
      case R12: return r12d;
      case RBP: return ebp;
      case RBX: return ebx;
      case R11: return r11d;
      case R10: return r10d;
      case R9:  return r9d;
      case R8:  return r8d;
      case RAX: return eax;
      case RCX: return ecx;
      case RDX: return edx;
      case RSI: return esi;
      case RDI: return edi;
      }
      assert(0);
    case 16:
      switch(r.index) {
      case R15: return r15w;
      case R14: return r14w;
      case R13: return r13w;
      case R12: return r12w;
      case RBP: return bp;
      case RBX: return bx;
      case R11: return r11w;
      case R10: return r10w;
      case R9:  return r9w;
      case R8:  return r8w;
      case RAX: return ax;
      case RCX: return cx;
      case RDX: return dx;
      case RSI: return si;
      case RDI: return di;
      }
      assert(0);
    case 8:
      switch(r.index) {

      }
    }
    assert(0);
  }

  static auto& get_asm_register_from_sys(int i) {
    register_info r;
    r.index = i;
    r.size = 64;
    return get_asm_register_from_rinfo(r);
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

  // this function takes a function that is provided the register type since asmjit uses multiple types
  // and they can't be corressed together
  template<typename func_t>
  auto get_asm_register_from_ud(ud_type t, func_t func) {
    using namespace asmjit;
    using namespace x86;
    switch(t) {
    case UD_R_AL ... UD_R_GS:
      return func(get_asm_register_from_rinfo(ud_register_to_rinfo(t)));
    case UD_R_XMM0 ... UD_R_XMM15:
      return func(x86RegData.xmm[t - UD_R_XMM0]);
    case UD_R_MM0 ... UD_R_MM7:
      return func(x86RegData.mm[t - UD_R_MM0]);
    case UD_R_ST0 ... UD_R_ST7:
      return func(x86RegData.fp[t - UD_R_ST0]);
    case UD_R_YMM0 ... UD_R_YMM15:
      return func(x86RegData.ymm[t - UD_R_YMM0]);
    case UD_NONE:
    default: assert(0);
    }
  }

  // asmjit::Operand get_asm_op_from_ud(ud_operand_t *opr);

}


#endif // REDMAGIC_ALIGN_UDIS_ASMJIT_H_
