#include "jit_internal.h"
#include "tracer.h"

#include <iostream>

using namespace redmagic;
using namespace std;

namespace redmagic {
  extern Manager *manager;
}


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
  tracer->Run(other_stack);

  // can not return from this method
  assert(0);
}

extern "C" void red_asm_start_tracing(void*, void*, void*, void*);
extern "C" void red_asm_ret_only();

void __attribute__ ((optimize("O2"))) Tracer::Start() {

  set_pc((uint64_t)&red_asm_ret_only);

  red_asm_start_tracing(NULL, (void*)&red_begin_tracing, this, stack - sizeof(stack));
}


void Tracer::Run(void *other_stack) {
  regs_struct = (struct user_regs_struct*)other_stack;

  mem_loc_t current_location;
  mem_loc_t last_location;
  mem_loc_t generated_location;
  struct jump_instruction_info jmp_info;

  while(true) {
    assert(before_stack == 0xdeadbeef);
    assert(after_stack == 0xdeadbeef);
    generated_location = buffer->getRawBuffer() + buffer->getOffset();
    last_location = current_location = udis_loc;
    while(ud_disassemble(&disassm)) {
      cout << "[0x" << std::hex << ud_insn_off(&disassm) << std::dec << "] " << ud_insn_asm(&disassm) << "\t" << ud_insn_hex(&disassm) <<  endl << flush;
      jmp_info = decode_instruction();
      if(jmp_info.is_jump)
        break;
      last_location = udis_loc;
      //CodeBuffer one_ins(ud_insn_off(&disassm), ud_insn_len(&disassm));
      //buffer->writeToEnd(one_ins);
    }
    if(current_location != last_location) {
      CodeBuffer ins_set(current_location, last_location - current_location);
      buffer->writeToEnd(ins_set);

      write_interrupt_block();
      continue_program(generated_location);
    }
    evaluate_instruction();



  }
}


// void Tracer::tracer_start_cb(intptr_t ptr) {
//   Tracer *t = (Tracer*)ptr;
//   t->Run();
//   assert(0);
// }


extern "C" void* red_asm_resume_eval_block(void*, void*);

void Tracer::continue_program(mem_loc_t resume_loc) {
  assert(regs_struct->rsp == (register_t)regs_struct);
  regs_struct->rsp += move_stack_by;
  move_stack_by = 0;
  *((register_t*)(regs_struct->rsp + TRACE_STACK_OFFSET - 448 /* hardcode offset to find jump to loc */)) = resume_loc;
  regs_struct = (struct user_regs_struct*)red_asm_resume_eval_block(&resume_struct, regs_struct);

}

extern "C" void red_asm_resume_tracer_block_start();
extern "C" void red_asm_resume_tracer_block_end();

namespace {
  CodeBuffer cb_interrupt_block((mem_loc_t)&red_asm_resume_tracer_block_start, (size_t)((mem_loc_t)&red_asm_resume_tracer_block_end - (mem_loc_t)&red_asm_resume_tracer_block_start));
}

#define ASM_BLOCK(label)                                    \
  extern "C" void red_asm_ ## label ## _start();            \
  extern "C" void red_asm_ ## label ## _end();              \
  namespace {                                               \
    CodeBuffer cb_asm_ ## label ((mem_loc_t)&red_asm_ ## label ## _start, (size_t)((mem_loc_t)&red_asm_ ## label ## _end - (mem_loc_t)&red_asm_ ## label ## _start)); \
  }

ASM_BLOCK(pop_stack);
ASM_BLOCK(push_stack);
ASM_BLOCK(call_direct);


void Tracer::write_interrupt_block() {
  // write a block that will return control back to this program
  auto offset = buffer->getOffset();
  auto written = buffer->writeToEnd(cb_interrupt_block);
  written.replace_stump<uint64_t>(0xfafafafafafafafa, (uint64_t)&resume_struct);
  buffer->setOffset(offset);
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
    assert(0);
  }
  case UD_Ijcxz:
  case UD_Ijecxz:
  case UD_Ijrcxz: {
    assert(0);
  }
  case UD_Ijmp: {
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    if(opr->type == UD_OP_IMM || opr->type == UD_OP_JIMM) {
      if(opr->type == UD_OP_IMM) {
        switch(opr->size) {
        case 32:
          set_pc(udis_loc & ~0xffffffff | opr->lval.udword);
          break;
        default:
          assert(0);
        }
      } else {
        assert(opr->type == UD_OP_JIMM);
        switch(opr->size) {
        case 8:
          set_pc(udis_loc + opr->lval.sbyte);
          break;
        case 16:
          set_pc(udis_loc + opr->lval.sword);
          break;
        case 32:
          set_pc(udis_loc + opr->lval.sdword);
          break;
        default:
          assert(0);
        }
      }
    } else {
      assert(0);
    }
    return;
  }
  case UD_Icall: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0);
    const ud_operand_t *opr2 = ud_insn_opr(&disassm, 1);
    assert(opr2 == NULL); // not 100% sure what the second opr would be used for

    register_t ret_addr = ud_insn_off(&disassm) + ud_insn_len(&disassm);

    if(opr1->type == UD_OP_IMM || opr1->type == UD_OP_JIMM) {
      if(opr1->type == UD_OP_IMM) {
        switch(opr1->size) {
        case 32:
          set_pc(udis_loc & ~0xffffffff | opr1->lval.udword);
          break;
        default:
          assert(0);
        }
      } else {
        assert(opr1->type == UD_OP_JIMM);
        switch(opr1->size) {
        case 16:
          set_pc(udis_loc + opr1->lval.sword);
          break;
        case 32:
          set_pc(udis_loc + opr1->lval.sdword);
          break;
        default:
          assert(0);
        }
      }
    } else {
      assert(0);
      // vtable branching
    }

    if(!redmagic::manager->should_trace_method((void*)udis_loc)) {
      // check if this is some method that we should avoid inlining
      auto buf_loc = buffer->getRawBuffer() + buffer->getOffset();
      auto written = buffer->writeToEnd(cb_asm_call_direct);
      written.replace_stump<uint64_t>(0xfafafafafafafafa, udis_loc);
      set_pc(ret_addr);

      write_interrupt_block();
      continue_program(buf_loc);

    } else {
      // inline this method, so push the return address and continue
      auto written = buffer->writeToEnd(cb_asm_push_stack);
      written.replace_stump<uint64_t>(0xfafafafafafafafa, ret_addr);
      push_stack(ret_addr);
    }

    return;
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
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    assert(opr == NULL);
    buffer->writeToEnd(cb_asm_pop_stack);
    set_pc(pop_stack());
    return;
  }

  case UD_Iinvalid: {
    cerr << "no idea: " << ud_insn_hex(&disassm) << endl;
    assert(0);
  }

  default: {
    assert(0);
  }
  }

}
