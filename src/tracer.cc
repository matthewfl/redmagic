#include "jit_internal.h"
#include "tracer.h"

#include <iostream>

using namespace redmagic;
using namespace std;


static int udis_input_hook (ud_t *ud) {
  Tracer *t = (Tracer*)ud_get_user_opaque_data(ud);
  mem_loc_t l = t->_get_udis_location();
  return (int)*((uint8_t*)l);
}

Tracer::Tracer(shared_ptr<CodeBuffer> buffer) {
  this->buffer = buffer;

  ud_init(&disassm);
  ud_set_user_opaque_data(&disassm, this);
  ud_set_input_hook(&disassm, udis_input_hook);
  ud_set_mode(&disassm, 64); // 64 bit
  ud_set_vendor(&disassm, UD_VENDOR_INTEL);
  ud_set_syntax(&disassm, UD_SYN_INTEL);

}


extern "C" void red_begin_tracing(void *other_stack, void* __, Tracer* tracer) {

  //tracer->regs_struct = other_stack;
  tracer->Run();

  // can not return from this method
  assert(0);
}

extern "C" void red_asm_start_tracing(void*, void*, void*, void*);

void Tracer::Start() {
  using namespace boost::context;

  void *start_end_addr = &&tracer_start_end;
  set_pc((uint64_t)start_end_addr);

  red_asm_start_tracing(NULL, (void*)&red_begin_tracing, this, stack - sizeof(stack));
 tracer_start_end:
  return;
}


void Tracer::Run() {
  mem_loc_t current_location;
  mem_loc_t last_location;
  struct jump_instruction_info jmp_info;

  while(true) {

    current_location = udis_loc;
    while(ud_disassemble(&disassm)) {
      cout << "[0x" << std::hex << ud_insn_off(&disassm) << std::dec << "] " << ud_insn_asm(&disassm) << "\t" << ud_insn_hex(&disassm) <<  endl << flush;
      jmp_info = decode_instruction();
      if(jmp_info.is_jump)
        break;
      last_location = udis_loc;
      //CodeBuffer one_ins(ud_insn_off(&disassm), ud_insn_len(&disassm));
      //buffer->writeToEnd(one_ins);
    }
    CodeBuffer ins_set(current_location, last_location - current_location);
    buffer->writeToEnd(ins_set);

    write_interupt_block();

    continue_program(current_location);



  }
}


void Tracer::tracer_start_cb(intptr_t ptr) {
  Tracer *t = (Tracer*)ptr;
  t->Run();
  assert(0);
}


extern "C" void* red_asm_resume_eval_block(void*, void*);

void Tracer::continue_program(mem_loc_t resume_loc) {
  ((register_t*)regs_struct)[-1] = resume_loc;
  regs_struct = (struct user_regs_struct*)red_asm_resume_eval_block(&resume_struct, regs_struct);
}

extern "C" void red_asm_resume_tracer_block_start();
extern "C" void red_asm_resume_tracer_block_end();

namespace {
  CodeBuffer cb_interupt_block((mem_loc_t)&red_asm_resume_tracer_block_start, (size_t)((mem_loc_t)&red_asm_resume_tracer_block_end - (mem_loc_t)&red_asm_resume_tracer_block_start));
}



void Tracer::write_interupt_block() {
  // write a block that will return control back to this program
  auto written = buffer->writeToEnd(cb_interupt_block);
  written.replace_stump<uint64_t>(0xfafafafafafafafa, (uint64_t)&resume_struct);
}

void Tracer::set_pc(uint64_t l) {
  udis_loc = l;
  ud_set_pc(&disassm, l);
}

struct jump_instruction_info Tracer::decode_instruction() {

  struct jump_instruction_info ret;

  switch(ud_insn_mnemonic(&disassm)) {
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
  case UD_Ijg: {
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    assert(opr->type == UD_OP_JIMM);
    ret.is_local_jump = true;
    ret.is_jump = true;
    switch(opr->size) {
    case 8:
      ret.local_jump_location = opr->lval.sbyte;
      break;
    case 16:
      ret.local_jump_location = opr->lval.sword;
      break;
    default:
      assert(0);
    }
    return ret;
  }
  case UD_Ijcxz:
  case UD_Ijecxz:
  case UD_Ijrcxz: {
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    assert(opr->type == UD_OP_JIMM);
    ret.is_local_jump = true;
    ret.is_jump = true;
    switch(opr->size) {
    case 8:
      ret.local_jump_location = opr->lval.sbyte;
      break;
    case 16:
      ret.local_jump_location = opr->lval.sword;
      break;
    default:
      assert(0);
    }
    return ret;
  }
  case UD_Ijmp: {
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    if(opr->type == UD_OP_JIMM) {
      ret.is_local_jump = true;
      switch(opr->size) {
      case 8:
        ret.local_jump_location = opr->lval.sbyte;
        break;
      case 16:
        ret.local_jump_location = opr->lval.sword;
        break;
      default:
        assert(0);
      }
    }
    ret.is_jump = true;
    return ret;
  }
  case UD_Icall: {
    ret.is_jump = true;
    return ret;
  }
  case UD_Iiretw:
  case UD_Iiretd:
  case UD_Iiretq: {
    // these should not be found
    perror("interupt return instructions?");

    ::exit(1);
  }
  case UD_Iret:
  case UD_Iretf: {
    ret.is_jump = true;
    return ret;
  }

  case UD_Iinvalid: {
    cerr << "no idea: " << ud_insn_hex(&disassm) << endl;
    assert(0);
  }

  default: {
    return ret;
  }
  }

}

void Tracer::evaluate_instruction() {

}
