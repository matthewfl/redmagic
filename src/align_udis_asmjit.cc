#include "align_udis_asmjit.h"

using namespace redmagic;
using namespace asmjit;


struct aligned_instruction_info {
  enum ud_mnemonic_code ud_code;
  enum X86InstId asm_code;
};

static aligned_instruction_info aligned_instructions[UD_MAX_MNEMONIC_CODE];

namespace {
#define MANUAL_ALIGN(UD_I, ASM_I)             \
  aligned_instructions[UD_I].ud_code = UD_I ; \
  aligned_instructions[UD_I].asm_code = ASM_I ;

  struct _do_alignment {
    _do_alignment() {
      for(int ud_i = 0; ud_i < UD_MAX_MNEMONIC_CODE; ud_i++) {
        enum ud_mnemonic_code ud_c = (enum ud_mnemonic_code)ud_i;
        const char *name = ud_lookup_mnemonic(ud_c);
        // if can't find instruction then returns  kX86InstIdNone
        uint32_t asm_id = X86Util::getInstIdByName(name);
        aligned_instructions[ud_c].ud_code = ud_c;
        aligned_instructions[ud_c].asm_code = (enum X86InstId)asm_id;
      }

      MANUAL_ALIGN(UD_Ijcxz, kX86InstIdJecxz);
      MANUAL_ALIGN(UD_Ipopfd, kX86InstIdPopf);
      MANUAL_ALIGN(UD_Ipopfq, kX86InstIdPopf);
      MANUAL_ALIGN(UD_Ipopfw, kX86InstIdPopf);
      MANUAL_ALIGN(UD_Ipushfd, kX86InstIdPushf);
      MANUAL_ALIGN(UD_Ipushfq, kX86InstIdPushf);
      MANUAL_ALIGN(UD_Ipushfw, kX86InstIdPushf);
    }
  } _do_alignment_inst;
}

enum X86InstId AlignedInstructions::get_asm_mnem(enum ud_mnemonic_code mnem) {
  return aligned_instructions[mnem].asm_code;
}


AlignedInstructions::AlignedInstructions(ud_t *disassm) {
  ud_mnem = ud_insn_mnemonic(disassm);
  pc = ud_insn_off(disassm);
  len = ud_insn_len(disassm);

  for(int i = 0;; i++) {
    const ud_operand_t *opr = ud_insn_opr(disassm, i);
    if(opr == NULL)
      break;
    number_operands = i + 1;
    operand_info *info = &operands[i];
    info->type = opr->type;
    switch(opr->type) {
    case UD_OP_IMM:
    case UD_OP_CONST:
      switch(opr->size) {
      case 8:
        info->imm_value = opr->lval.sbyte;
        break;
      case 16:
        info->imm_value = opr->lval.sword;
        break;
      case 32:
        info->imm_value = opr->lval.sdword;
        break;
      case 64:
        info->imm_value = opr->lval.sqword;
        break;
      default:
        assert(0);
      }
      break;
    case UD_OP_JIMM:
      switch(opr->size) {
      case 8:
        info->address = pc + opr->lval.sbyte;
        break;
      case 16:
        info->address = pc + opr->lval.sword;
        break;
      case 32:
        info->address = pc + opr->lval.sdword;
        break;
      case 64:
        info->address = pc + opr->lval.sqword;
        break;
      default:
        assert(0);
      }
      break;
    case UD_OP_REG: {
      info->register_i = ud_register_to_rinfo(opr->base);
      break;
    }
    case UD_OP_MEM: {
      info->base_register = info->index_register = {-1};
      info->index_scale = 0;
      if(opr->base != UD_NONE)
        info->base_register = ud_register_to_rinfo(opr->base);
      if(opr->index != UD_NONE) {
        info->index_register = ud_register_to_rinfo(opr->index);
        info->index_scale = opr->scale;
      }
      switch(opr->offset) {
      case 8:
        info->offset = opr->lval.sbyte;
        break;
      case 16:
        info->offset = opr->lval.sword;
        break;
      case 32:
        info->offset = opr->lval.sdword;
        break;
      case 64:
        info->offset = opr->lval.sqword;
        break;
      default:
        assert(0);
      }
      break;
    }
    case UD_OP_PTR:
      assert(0);
    default:
      assert(0);
    }
  }
}

const asmjit::Operand AlignedInstructions::get_asm_op(unsigned int i) {
  assert(i < number_operands);
  operand_info *info = &operands[i];

  switch(info->type) {
  case UD_OP_CONST:
  case UD_OP_IMM:
    return imm(info->imm_value);
  case UD_OP_JIMM:
    return imm_u(info->address);
  case UD_OP_REG:
    return get_asm_register_from_rinfo(info->register_i);
  case UD_OP_MEM: {
    if(info->base_register.index != -1) {
      if(info->index_register.index == -1) {
        return x86::word_ptr(get_asm_register_from_rinfo(info->base_register), info->offset);
      }
      int scale = 0;

      switch(info->index_scale) {
      case  0: scale = 0; break;
      case  2: scale = 1; break;
      case  4: scale = 2; break;
      case  8: scale = 3; break;
      case 16: scale = 4; break;
      case 32: scale = 5; break;
      case 64: scale = 6; break;
      default: assert(0);
      }
      return x86::word_ptr(get_asm_register_from_rinfo(info->base_register), get_asm_register_from_rinfo(info->index_register), scale, info->offset);
    } else {
      // there is no base register
      assert(info->index_register.index != -1);
      int scale = 0;
      switch(info->index_scale) {
      case  0: scale = 0; break;
      case  2: scale = 1; break;
      case  4: scale = 2; break;
      case  8: scale = 3; break;
      case 16: scale = 4; break;
      case 32: scale = 5; break;
      case 64: scale = 6; break;
      default: assert(0);
      }
      return x86::ptr_abs(0, get_asm_register_from_rinfo(info->index_register), scale, info->offset);
    }
  }
  default:
    assert(0);
  }
}

uint64_t AlignedInstructions::registers_used() {
  uint64_t ret = 0;
  for(int i = 0; i < number_operands; i++) {
    operand_info *info = &operands[i];
    switch(info->type) {
    case UD_OP_REG: {
      ret |= 1 << info->register_i.index;
      break;
    }
    case UD_OP_MEM: {
      if(info->base_register.index != -1)
        ret |= 1 << info->base_register.index;
      if(info->index_register.index != -1)
        ret |= 1 << info->index_register.index;
      break;
    }
    case UD_OP_CONST:
    case UD_OP_IMM:
    case UD_OP_JIMM:
      break;
    default:
      assert(0);
    }
  }
  return ret;
}

void AlignedInstructions::ReplaceReigster(int from, int to) {
  bool did_replace = false;

  for(int i = 0; i < number_operands; i++) {
    operand_info *info = &operands[i];
    switch(info->type) {
    case UD_OP_REG: {
      if(info->register_i.index == from) {
        did_replace = true;
        info->register_i.index = to;
      }
      break;
    }
    case UD_OP_MEM: {
      if(info->base_register.index == from) {
        did_replace = true;
        info->base_register.index = to;
      }
      if(info->index_register.index == from) {
        did_replace = true;
        info->index_register.index = to;
      }
      break;
    }
    case UD_OP_CONST:
    case UD_OP_IMM:
    case UD_OP_JIMM:
      break;
    default:
      assert(0);
    }
  }

  assert(did_replace);
}


void AlignedInstructions::Emit(asmjit::Assembler *assem) {
  enum X86InstId inst = get_asm_mnem();
  assert(inst != kX86InstIdNone);
  switch(number_operands) {
  case 0:
    assem->emit(inst);
    return;
  case 1:
    assem->emit(inst, get_asm_op(0));
    return;
  case 2:
    assem->emit(inst, get_asm_op(0), get_asm_op(1));
    return;
  case 3:
    assem->emit(inst, get_asm_op(0), get_asm_op(1), get_asm_op(2));
    return;
  default:
    assert(0);
  }
}
