#include "compiler.h"

using namespace redmagic;

#include <iostream>
using namespace std;

Compiler::Compiler(
#ifdef CONF_COMPILE_IN_PARENT
                   Tracer *tracer
#else
                   std::vector<JumpTrace> &&traces
#endif
                   ) {
#ifdef CONF_COMPILE_IN_PARENT
  _tracer = tracer;
  traces = std::move(_tracer->traces);
#else
  this->traces = std::move(traces);
#endif
}

unsigned char Compiler::readByte(mem_loc_t where) {
#ifdef CONF_COMPILE_IN_PARENT
  return _tracer->readByte(where);
#else
  // then we are in the same process as where we want to read from, so we can directly read
  return *(unsigned char*)where;
#endif
}


namespace redmagic {
  size_t relocate_code(ud_t *source, void *dest, size_t length, size_t output_limit) {
    size_t dest_len = 0;
    size_t processed_len = 0;
    while(processed_len < length && dest_len < output_limit) {
      processed_len += ud_disassemble(source);

      switch(ud_insn_mnemonic(source)) {

      }
    }

    return dest_len;

  }

  static int64_t get_opr_val_signed(const ud_operand_t *opr) {
    switch(opr->size) {
    case 8:
      return opr->lval.sbyte;
    case 16:
      return opr->lval.sword;
    case 32:
      return opr->lval.sdword;
    case 64:
      return  opr->lval.sqword;
    default:
      assert(0);
    }
  }

  std::vector<mem_loc_t> find_jumps(ud_t *disassm, size_t size) {
    std::vector<mem_loc_t> ret;

    size_t processed = 0;
    while(processed < size) {
      uint64_t ilen = ud_disassemble(disassm);
      processed += ilen;
      uint64_t ioff = ud_insn_off(disassm);
      switch(ud_insn_mnemonic(disassm)) {
      case UD_Ijo:
      case UD_Ijno:
      case UD_Ijb:
      case UD_Ijae:
      case UD_Ijz:
      case UD_Ijnz:
      case UD_Ijbe:
      case UD_Ija:
      case UD_Ijs:
      case UD_Ijns:
      case UD_Ijp:
      case UD_Ijnp:
      case UD_Ijl:
      case UD_Ijge:
      case UD_Ijle:
      case UD_Ijg:


      case UD_Ijcxz:
      case UD_Ijecxz:
      case UD_Ijrcxz:

      case UD_Ijmp:

      case UD_Icall:

        {
          const ud_operand_t *opr = ud_insn_opr(disassm, 0);
          if(opr->type == UD_OP_JIMM) {
            int64_t jmpo = get_opr_val_signed(opr);
            if(jmpo < 0 && -jmpo > (processed - ilen))
              ret.push_back(ioff);
            else if(jmpo > 0 && jmpo > (size - (processed - ilen)))
              ret.push_back(ioff);
          } else {
            ret.push_back(ioff);
          }
          // assuming that this would be a not allowed value?
          // maybe to a constant memory location?
          assert(opr->type != UD_OP_CONST);
          break;
        }

      case UD_Iiretw:
      case UD_Iiretd:
      case UD_Iiretq:
        // these should not be found
        perror("interupt return instructions?");

      case UD_Iret:
      case UD_Iretf:
        perror("return instruction");


      case UD_Iinvalid: {
        cerr << "no idea: " << ud_insn_hex(disassm) << endl;
      }

      default: { }
      }
    }

    return ret;
  }

}
