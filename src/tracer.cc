#include "jit_internal.h"
#include "tracer.h"

#include "simple_compiler.h"

#include <string.h>

#include <dlfcn.h>

#include "align_udis_asmjit.h"

using namespace redmagic;
using namespace std;

namespace redmagic {
  extern Manager *manager;
}


extern "C" void red_asm_resume_tracer_block_start();
extern "C" void red_asm_resume_tracer_block_end();

namespace {
  CodeBuffer cb_interrupt_block((mem_loc_t)&red_asm_resume_tracer_block_start, (size_t)((mem_loc_t)&red_asm_resume_tracer_block_end - (mem_loc_t)&red_asm_resume_tracer_block_start));
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
  ud_set_syntax(&disassm, UD_SYN_ATT);


  auto written = buffer->writeToEnd(cb_interrupt_block);
  written.replace_stump<uint64_t>(0xfafafafafafafafa, (uint64_t)&resume_struct);

  interrupt_block_location = written.getRawBuffer();
}


void red_begin_tracing(void *other_stack, void* __, Tracer* tracer) {

  //tracer->regs_struct = other_stack;
  tracer->Run(other_stack);

  // can not return from this method
  assert(0);
}

extern "C" void red_asm_start_tracing(void*, void*, void*, void*);
extern "C" void red_asm_begin_block();

extern "C" void _dl_runtime_resolve();
extern "C" void _dl_fixup();

void* Tracer::Start(void *start_addr) {

  set_pc((mem_loc_t)start_addr);
  //set_pc((uint64_t)&red_asm_ret_only);

  //red_asm_start_tracing(NULL, (void*)&red_begin_tracing, this, stack - sizeof(stack));

  using namespace asmjit;
  SimpleCompiler compiler(buffer.get());
  //compiler.mov(x86::rdx, x86::rsp);
  compiler.mov(x86::rdx, imm_ptr(this)); // argument 3
  compiler.mov(x86::rsi, imm_ptr(&red_begin_tracing));
  resume_struct.stack_pointer = (register_t)stack - sizeof(stack) + sizeof(mem_loc_t);
  *(void**)(stack - sizeof(stack) + sizeof(mem_loc_t)) = (void*)&red_asm_begin_block;
  //compiler.mov(x86::rsp, imm_ptr(stack - sizeof(stack)));
  //compiler.push(imm_ptr(red_begin_tracing));
  compiler.jmp(imm_u(interrupt_block_location));
  auto written = compiler.finalize();


  return (void*)written.getRawBuffer();
  //return (void*)&red_begin_tracing;
}

// abort after some number of instructions to see if there is an error with the first n instructions
// useful for bisecting which instruction is failing if there is an error
#define ABORT_BEFORE 110




void Tracer::Run(void *other_stack) {
  regs_struct = (struct user_regs_struct*)other_stack;

  current_location = udis_loc;

  while(true) {
    assert(before_stack == 0xdeadbeef);
    assert(after_stack == 0xdeadbeef);
    generated_location = buffer->getRawBuffer() + buffer->getOffset();
    last_location = udis_loc;
    assert(current_location == last_location);
  processes_instructions:
    while(ud_disassemble(&disassm)) {

      Dl_info dlinfo;
      dladdr((void*)ud_insn_off(&disassm), &dlinfo);

      auto ins_loc = ud_insn_off(&disassm);

      fprintf(stderr, "%8i\t%-35s [%#016lx %-40s] %s\n", ++icount, ud_insn_asm(&disassm), ins_loc, dlinfo.dli_sname, ud_insn_hex(&disassm));
      fflush(stderr);

      jmp_info = decode_instruction();
      if(jmp_info.is_jump)
        goto run_instructions;

      for(int i = 0;; i++) {
        const ud_operand_t *opr = ud_insn_opr(&disassm, i);
        if(opr == NULL)
          break;
        assert(opr->type != UD_OP_PTR); // ?
        if((opr->type == UD_OP_REG || opr->type == UD_OP_MEM) &&
           (opr->base == UD_R_RIP || opr->index == UD_R_RIP)) {
          rip_used = true;
          goto run_instructions;
        }
        //assert(opr->base != UD_R_RIP && opr->index != UD_R_RIP);
      }
#ifdef ABORT_BEFORE
      if(icount >= ABORT_BEFORE)
        goto run_instructions;
#endif
      last_location = udis_loc;
    }
  run_instructions:
    if(current_location != last_location) {
      {
        CodeBuffer ins_set(current_location, last_location - current_location);
        buffer->writeToEnd(ins_set);
      }

      current_location = last_location;
      write_interrupt_block();
      continue_program(generated_location);
    }
#ifdef ABORT_BEFORE
    if(icount >= ABORT_BEFORE)
      abort();
#endif
  rewrite_instructions:
    regs_struct->rip = udis_loc;
    if(rip_used) {
      generated_location = buffer->getRawBuffer() + buffer->getOffset();
      replace_rip_instruction();
      // we have to evaluate this instruction which has been written
      current_location = udis_loc;
      write_interrupt_block();
      continue_program(generated_location);
    } else {
      // this is a jump instruction that we are evaluating and replacing
      evaluate_instruction();
      current_location = udis_loc;
    }
    rip_used = false;
  }
}


extern "C" void* red_asm_resume_eval_block(void*, void*);

void Tracer::continue_program(mem_loc_t resume_loc) {
  assert(regs_struct->rsp - TRACE_STACK_OFFSET == (register_t)regs_struct);
  regs_struct->rsp += move_stack_by;
  move_stack_by = 0;
  *((register_t*)(regs_struct->rsp - TRACE_RESUME_ADDRESS_OFFSET)) = resume_loc;
  regs_struct = (struct user_regs_struct*)red_asm_resume_eval_block(&resume_struct, regs_struct);

}


#define ASM_BLOCK(label)                                    \
  extern "C" void red_asm_ ## label ## _start();            \
  extern "C" void red_asm_ ## label ## _end();              \
  static CodeBuffer cb_asm_ ## label ((mem_loc_t)&red_asm_ ## label ## _start, (size_t)((mem_loc_t)&red_asm_ ## label ## _end - (mem_loc_t)&red_asm_ ## label ## _start));

//   // [all cap name, %reg name, reg struct offset]
// #define MAIN_REGISTERS(METHOD)  \
//   METHOD(R15, %r15, 0)        \
//   METHOD(R14, %r14, 8)        \
//   METHOD(R13, %r13, 16)       \
//   METHOD(R12, %r12, 24)       \
//   METHOD(RBP, %rbp, 32)       \
//   METHOD(RBX, %rbx, 40)       \
//   METHOD(R11, %r11, 48)       \
//   METHOD(R10, %r10, 56)       \
//   METHOD(R9,  %r9,  64)       \
//   METHOD(R8,  %r8,  72)       \
//   METHOD(RAX, %rax, 80)       \
//   METHOD(RCX, %rcx, 88)       \
//   METHOD(RDX, %rdx, 96)       \
//   METHOD(RSI, %rsi, 104)      \
//   METHOD(RDI, %rdi, 112)

// #define NUMBER_MAIN_REGISTERS 15

// struct group_register_instructions_s {
//   int register_index;
//   CodeBuffer instruction;
// };

ASM_BLOCK(pop_stack);
ASM_BLOCK(push_stack);
ASM_BLOCK(call_direct);


void Tracer::write_interrupt_block() {
  // write a block that will return control back to this program
  auto offset = buffer->getOffset();
  // auto written = buffer->writeToEnd(cb_interrupt_block);
  // written.replace_stump<uint64_t>(0xfafafafafafafafa, (uint64_t)&resume_struct);
  {
    SimpleCompiler compiler(buffer.get());
    compiler.jmp(asmjit::imm_u(interrupt_block_location));
  }
  buffer->setOffset(offset);
}

void Tracer::set_pc(uint64_t l) {
  udis_loc = l;
  ud_set_pc(&disassm, l);
}

Tracer::opr_value Tracer::get_opr_value(const ud_operand_t *opr) {
  struct opr_value ret;

  ret.type = opr->type;
  ret.is_ptr = false;

  switch(opr->type) {
  case UD_OP_IMM:
  case UD_OP_CONST:
    switch(opr->size) {
      // not sure if should return these signed
    case 8:
      ret.value = opr->lval.sbyte;
      return ret;
    case 16:
      ret.value = opr->lval.sword;
      return ret;
    case 32:
      ret.value = opr->lval.sdword;
      return ret;
    case 64:
      ret.value = opr->lval.sqword;
      return ret;
    }
  case UD_OP_JIMM:
    switch(opr->size) {
    case 8:
      ret.address = opr->lval.sbyte + udis_loc;
      return ret;
    case 16:
      ret.address = opr->lval.sword + udis_loc;
      return ret;
    case 32:
      ret.address = opr->lval.sdword + udis_loc;
      return ret;
    case 64:
      ret.address = opr->lval.sqword + udis_loc;
      return ret;
    }
  case UD_OP_REG: {
    int r = ud_register_to_sys(opr->base);
    assert(r != -1);
    ret.value = ((register_t*)regs_struct)[r];
    return ret;
  }
  case UD_OP_MEM: {
    int ri = ud_register_to_sys(opr->base);
    assert(ri != -1);
    register_t rv = ((register_t*)regs_struct)[ri];
    if(opr->index != UD_NONE) {
      int ii = ud_register_to_sys(opr->index);
      register_t iv = ((register_t*)regs_struct)[ii];
      switch(opr->scale) {
      case 1:
        break;
      case 2:
        iv <<= 1;
        break;
      case 4:
        iv <<= 2;
        break;
      case 8:
        iv <<= 3;
        break;
      default:
        assert(0);
      }
      rv += iv;
    }
    switch(opr->offset) {
    case 8:
      rv += opr->lval.sbyte;
      break;
    case 16:
      rv += opr->lval.sword;
      break;
    case 32:
      rv += opr->lval.sdword;
      break;
    case 64:
      rv += opr->lval.sqword;
      break;
    default:
      assert(0);
    }
    ret.address = rv;
    ret.is_ptr = true;
    return ret;
    //return *(register_t*)rv;
  }
  case UD_OP_PTR:
    assert(0);
  }

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
    case 32:
      ret.local_jump_location = opr->lval.sdword;
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
      case 32:
        ret.local_jump_location = opr->lval.sdword;
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
    //cerr << "no idea: " << ud_insn_hex(&disassm) << endl;
    fprintf(stderr, "no idea: %s\n", ud_insn_hex(&disassm));
    assert(0);
  }

  default: {
    return ret;
  }
  }

}


// page 522 in intel manual
struct conditional_jumps_opts {
  enum ud_mnemonic_code code;

  uint8_t true_encoding[4];
  uint8_t true_encoding_len;

  enum ud_mnemonic_code false_inst;

  uint32_t equals_zero; // all bits set must equal zero
  uint32_t equals_one; // all bits set must equal one
  //uint32_t or_equals_zero; // one bit must equal zero
  //uint32_t or_equals_one; // one bit must equal one
  uint32_t is_equals; // all bits set must equal eachother
  uint32_t not_equals; // all bits set must not equal eachother

  bool inverted; // if we want the expression to be false... b/c f-me

};

enum eflags_bits {
  eflag_cf = 1,
  eflag_pf = 1 << 2,
  eflag_af = 1 << 4,
  eflag_zf = 1 << 6,
  eflag_sf = 1 << 7,
  eflag_tf = 1 << 8,
  eflag_if = 1 << 9,
  eflag_df = 1 << 10,
  eflag_of = 1 << 11,
};

struct conditional_jumps_opts jump_opts[] = {
  { UD_Ijo,  { 0x0F, 0x80, 0xCD }, 3, UD_Ijno, 0, eflag_of, 0, 0, 0 },
  { UD_Ijno, { 0x0F, 0x81, 0xCD }, 3, UD_Ijo,  eflag_of, 0, 0, 0, 0 },
  { UD_Ijb,  { 0x0F, 0x82, 0xCD }, 3, UD_Ijae, 0, eflag_cf, 0, 0, 0 },
  { UD_Ijae, { 0x0F, 0x83, 0xCD }, 3, UD_Ijb,  eflag_cf, 0, 0, 0, 0 },
  { UD_Ijz,  { 0x0F, 0x84, 0xCD }, 3, UD_Ijnz, 0, eflag_zf, 0, 0, 0 },
  { UD_Ijnz, { 0x0F, 0x85, 0xCD }, 3, UD_Ijz,  eflag_zf, 0, 0, 0, 0 },
  { UD_Ijbe, { 0x0F, 0x86, 0xCD }, 3, UD_Ija,  eflag_cf | eflag_zf, 0, 0, 0, 1 },
  { UD_Ija,  { 0x0F, 0x87, 0xCD }, 3, UD_Ijbe, eflag_cf | eflag_zf, 0, 0, 0, 0 },
  { UD_Ijs,  { 0x0F, 0x88, 0xCD }, 3, UD_Ijns, 0, eflag_sf, 0, 0, 0 },
  { UD_Ijns, { 0x0F, 0x89, 0xCD }, 3, UD_Ijs,  eflag_sf, 0, 0, 0, 0 },
  { UD_Ijp,  { 0x0F, 0x8A, 0xCD }, 3, UD_Ijnp, 0, eflag_pf, 0, 0, 0 },
  { UD_Ijnp, { 0x0F, 0x8B, 0xCD }, 3, UD_Ijp,  eflag_pf, 0, 0, 0, 0 },
  { UD_Ijl,  { 0x0F, 0x8C, 0xCD }, 3, UD_Ijge, 0, 0, eflag_sf | eflag_of, 0 },
  { UD_Ijge, { 0x0F, 0x8D, 0xCD }, 3, UD_Ijl,  0, 0, eflag_sf | eflag_of, 0, 0 },
  { UD_Ijle, { 0x0F, 0x8E, 0xCD }, 3, UD_Ijg,  eflag_zf, 0, eflag_sf | eflag_of, 0, 1 },
  { UD_Ijg,  { 0x0F, 0x8F, 0xCD }, 3, UD_Ijle, eflag_zf, 0, eflag_sf | eflag_of, 0, 0 }
};

void Tracer::evaluate_instruction() {

  enum ud_mnemonic_code mnem = ud_insn_mnemonic(&disassm);

  switch(mnem) {
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
    int64_t joffset;
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    assert(opr->type == UD_OP_JIMM);
    switch(opr->size) {
    case 8:
      joffset = opr->lval.sbyte;
      break;
    case 16:
      joffset = opr->lval.sword;
      break;
    case 32:
      joffset = opr->lval.sdword;
      break;
    default:
      assert(0);
    }

    register_t eflags = regs_struct->eflags;
    mem_loc_t alternate_instructions; // instructions for the branch that we didn't take
    enum ud_mnemonic_code emit;

    for(int i = 0; i < sizeof(jump_opts); i++) {
      if(jump_opts[i].code == mnem) {
        bool expression =
          (!jump_opts[i].equals_zero || (jump_opts[i].equals_zero & eflags) == 0) &&
          (!jump_opts[i].equals_one || (jump_opts[i].equals_one & ~eflags) == 0) &&
          // (!jump_opts[i].or_equals_zero || (bits_set(jump_opts[i].or_equals_zero & eflags)) <= 1) &&
          // (!jump_opts[i].or_equals_one || (bits_set(jump_opts[i].or_equals_one & eflags)) >= 1) &&
          (!jump_opts[i].is_equals || (bits_set(jump_opts[i].is_equals & eflags) % 2) == 0) &&
          (!jump_opts[i].not_equals || (bits_set(jump_opts[i].not_equals & eflags) % 2) == 1);
        if(expression != jump_opts[i].inverted) {
          // this expression is true which means that we are taking the jump
          alternate_instructions = udis_loc;
          set_pc(udis_loc + joffset);
          emit = jump_opts[i].false_inst;
        } else {
          emit = mnem;
          alternate_instructions = udis_loc + joffset;
        }
        break;
      }
    }

    uint8_t lbuffer[16] = {
      0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa,
      0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa
    };

    uint8_t buffer_used = 0;

    for(int i = 0; i < sizeof(jump_opts); i++) {
      if(jump_opts[i].code == emit) {
        memcpy(lbuffer, jump_opts[i].true_encoding, jump_opts[i].true_encoding_len);
        buffer_used += jump_opts[i].true_encoding_len;

        buffer_used += 4; // the relative jump address
        CodeBuffer buff((mem_loc_t)&lbuffer, buffer_used);
        auto written = buffer->writeToEnd(buff);
        // TODO: make written do something to replace to jump address
        return;
      }
    }

    // something went wrong, we should not be here
    assert(0);
  }
  case UD_Ijcxz:
  case UD_Ijecxz:
  case UD_Ijrcxz: {
    assert(0);
  }
  case UD_Ijmp: {
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    mem_loc_t jump_dest = 0;

    if(opr->type == UD_OP_IMM || opr->type == UD_OP_JIMM) {
      if(opr->type == UD_OP_IMM) {
        switch(opr->size) {
        case 32:
          jump_dest = udis_loc & ~0xffffffff | opr->lval.udword;
          goto process_jump_dest;
        default:
          assert(0);
        }
      } else {
        assert(opr->type == UD_OP_JIMM);
        switch(opr->size) {
        case 8:
          jump_dest = udis_loc + opr->lval.sbyte;
          goto process_jump_dest;
        case 16:
          jump_dest = udis_loc + opr->lval.sword;
          goto process_jump_dest;
        case 32:
          jump_dest = udis_loc + opr->lval.sdword;
          goto process_jump_dest;
        default:
          assert(0);
        }
      }
    } else if(opr->type == UD_OP_REG) {
      assert(opr->index == UD_NONE);
      int ri = ud_register_to_sys(opr->base);
      assert(ri != -1);
      register_t rv = ((register_t*)regs_struct)[ri];
      // assert(ri < sizeof(test_register_instructions) / sizeof(group_register_instructions_s));
      // auto written = buffer->writeToEnd(test_register_instructions[ri].instruction);
      // written.replace_stump<uint64_t>(0xfafafafafafafafa, rv);

      SimpleCompiler compiler(buffer.get());
      compiler.TestRegister(ri, rv);
      auto written = compiler.finalize();

      jump_dest = rv;
    } else if(opr->type == UD_OP_MEM) {
      if(opr->base == UD_R_RIP) {
        // then we are going to assume that this is a constant value since this is relative to the rip
        auto v = get_opr_value(opr);
        mem_loc_t t = *(mem_loc_t*)v.address;
        if(t == udis_loc) {
          // this is what it looks like when there is some dynamic linked library and it is going to resolve its address
          // and the store it in the memory location that we have just read from

          printf("=============TODO: jumping to the next line to reolve an address, don't inline\n");
          abort();
        }
        jump_dest = t;
        //set_pc(*(mem_loc_t*)v.address);
      } else {
        assert(0);
      }
    }
    else {
      assert(0);
    }

    process_jump_dest:
    assert(jump_dest != 0);
    if(last_call_instruction + 1 == icount) {
      // then the first operation in this method was a jump, which means that we were probably jumping through a redirect with the dynamic linker
      if(!manager->should_trace_method((void*)jump_dest)) {
        buffer->setOffset(last_call_generated_op);
        pop_stack();
        set_pc(last_call_ret_addr);
        SimpleCompiler compiler(buffer.get());
        compiler.call(asmjit::imm_ptr(jump_dest));
        auto written = compiler.finalize();
        write_interrupt_block();
        continue_program(written.getRawBuffer());
        return;
      }
    }
    set_pc(jump_dest);
    return;
  }
  case UD_Icall: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0);
    const ud_operand_t *opr2 = ud_insn_opr(&disassm, 1);
    assert(opr2 == NULL); // not 100% sure what the second opr would be used for

    register_t ret_addr = ud_insn_off(&disassm) + ud_insn_len(&disassm);

    last_call_instruction = icount;

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
      // vtable branching
      opr_value ta = get_opr_value(opr1);
      assert(ta.is_ptr);
      register_t value = *ta.address_ptr;
      SimpleCompiler compiler(buffer.get());
      compiler.TestMemoryLocation(ta.address, value);
      compiler.finalize();
      set_pc(value);
    }

    last_call_generated_op = buffer->getOffset();
    last_call_ret_addr = ret_addr;

    if(!redmagic::manager->should_trace_method((void*)udis_loc)) {
      // check if this is some method that we should avoid inlining
      auto buf_loc = buffer->getRawBuffer() + buffer->getOffset();
      auto written = buffer->writeToEnd(cb_asm_call_direct);
      written.replace_stump<uint64_t>(0xfafafafafafafafa, udis_loc);
      set_pc(ret_addr);

      current_location = udis_loc;
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
    // cerr << "no idea: " << ud_insn_hex(&disassm) << endl;
    fprintf(stderr, "no idea: %s\n", ud_insn_hex(&disassm));
    assert(0);
  }

  default: {
    assert(0);
  }
  }

}


void Tracer::replace_rip_instruction() {

  enum ud_mnemonic_code mnem = ud_insn_mnemonic(&disassm);

  switch(mnem) {
  case UD_Ilea: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0); // dest address
    const ud_operand_t *opr2 = ud_insn_opr(&disassm, 1); // source address
    assert(opr1 != NULL && opr2 != NULL);
    assert(opr2->base == UD_R_RIP || opr2->index == UD_R_RIP); // assume that we are loading this address
    if(opr2->base == UD_R_RIP && opr2->index == UD_NONE) {
      opr_value val = get_opr_value(opr2);
      assert(val.is_ptr);
      assert(opr1->type == UD_OP_REG);
      int dest = ud_register_to_sys(opr1->base);
      // assert(dest < sizeof(set_register_instructions) / sizeof(group_register_instructions_s));

      // auto written = buffer->writeToEnd(set_register_instructions[dest].instruction);
      // written.replace_stump<uint64_t>(0xfafafafafafafafa, val.address);
      SimpleCompiler compiler(buffer.get());
      compiler.SetRegister(dest, val.address);
      return;
    }
    assert(0);
  }

  case UD_Imov: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0); // dest address
    const ud_operand_t *opr2 = ud_insn_opr(&disassm, 1); // source address
    assert(opr1 != NULL && opr2 != NULL);
    if(opr2->base == UD_R_RIP && opr2->index == UD_NONE) {
      // // then we are just reading some offset from this address
      opr_value val = get_opr_value(opr2);
      assert(val.is_ptr);
      assert(opr1->type == UD_OP_REG);
      int dest = ud_register_to_sys(opr1->base);

      SimpleCompiler compiler(buffer.get());
      compiler.MemToRegister(val.address, dest);
      return;
    }
    assert(0);
  }

  case UD_Ipush: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0);
    assert(opr1->index == UD_NONE);
    opr_value val = get_opr_value(opr1);
    assert(val.is_ptr);
    SimpleCompiler compiler(buffer.get());
    compiler.PushMemoryLocationValue(val.address);
    auto written = compiler.finalize();
    return;
  }

    //case UD_Ipush: // have to do push independently since the stack is moving
  case UD_Iadd:
  _auto_rewrite_register:
    {
      // automatically rewrite the registers that are being used
      // and then use the compiler to generate the approperate bytes
      AlignedInstructions ali(&disassm);
      uint64_t used_registers = ali.registers_used();
      assert((used_registers & (1 << RIP)) != 0);
      used_registers &= ~(1 << RIP);

      SimpleCompiler compiler(buffer.get());
      compiler.add_used_registers(used_registers);
      auto scr = compiler.get_scratch_register();
      compiler.mov(scr, udis_loc); // load the current rip into the scratch register
      ali.ReplaceReigster(RIP, get_sys_register_from_asm(scr));
      ali.Emit(&compiler);

      auto written = compiler.finalize();

      break;
    }


  case UD_Ijmp: {
    assert(0);
  }
  default: {
    AlignedInstructions ali(&disassm);



    assert(0);
  }
  }
}


void Tracer::abort() {
  printf("\n--ABORT--\n");
  continue_program(current_location);
}
