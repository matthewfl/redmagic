#include "jit_internal.h"
#include "tracer.h"

#include "simple_compiler.h"

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <dlfcn.h>

#include "align_udis_asmjit.h"


using namespace redmagic;
using namespace std;

namespace redmagic {
  extern Manager *manager;
  //extern thread_local Tracer *tracer;

  extern std::atomic<Tracer*> free_tracer_list;
}


extern "C" void red_asm_resume_tracer_block_start();
extern "C" void red_asm_resume_tracer_block_end();

namespace {
  CodeBuffer cb_interrupt_block((mem_loc_t)&red_asm_resume_tracer_block_start, (size_t)((mem_loc_t)&red_asm_resume_tracer_block_end - (mem_loc_t)&red_asm_resume_tracer_block_start));
}


static int loop_n = 0;

namespace redmagic {
  long global_icount = 0;
  // TODO: this is starting traces which then abort but really should branch back to normal code
  // thus it is causing crashes after a while.....
#ifdef CONF_GLOBAL_ABORT
  long global_icount_abort = -1; //776640 * 4;

  bool global_abort() {
    if(global_icount_abort != -1 && global_icount > global_icount_abort) {
      return true;
    }
    return false;
  }
#endif

#ifndef NDEBUG
  // using a conditional break point is much slower then having the check internally
  long global_debugger_int = -1;
#endif
}


extern "C" void red_asm_jump_rsi_temp_enable();
extern "C" void red_asm_jump_rsi_resume_trace();


static int udis_input_hook (ud_t *ud) {
  Tracer *t = (Tracer*)ud_get_user_opaque_data(ud);
  mem_loc_t l = t->_get_udis_location();
  return (int)*((uint8_t*)l);
}

Tracer::Tracer(CodeBuffer* buffer) {
  this->buffer = buffer;

  ud_init(&disassm);
  ud_set_user_opaque_data(&disassm, this);
  ud_set_input_hook(&disassm, udis_input_hook);
  ud_set_mode(&disassm, 64); // 64 bit
  ud_set_vendor(&disassm, UD_VENDOR_INTEL);
#ifdef CONF_VERBOSE
  ud_set_syntax(&disassm, UD_SYN_ATT);
#endif

  auto written = buffer->writeToEnd(cb_interrupt_block);
  written.replace_stump<uint64_t>(0xfafafafafafafafa, (uint64_t)&resume_struct);

  interrupt_block_location = written.getRawBuffer();

  // method_address_stack.reserve(100);
  // method_sp_stack.reserve(100);
  // method_sp_stack.push_back(-1);
  // merge_block_stack.reserve(100);
  // merge_block_stack.push_back(0);

  method_stack.reserve(100);
  method_stack.push_back(tracer_method_stack_s(0, -1));
  merge_block_stack.reserve(100);
  merge_block_stack.push_back(tracer_merge_block_stack_s());

  tracing_from = 0;
}

Tracer::~Tracer() {
  if(buffer != nullptr)
    CodeBuffer::Release(buffer);
}


void red_begin_tracing(struct user_regs_struct *other_stack, void* __, Tracer* tracer) {
  //tracer->regs_struct = other_stack;
  tracer->Run(other_stack);

  // can not return from this method
  assert(0);
  __builtin_unreachable();
}

extern "C" void red_resume_trace(mem_loc_t target_rip, mem_loc_t write_jump_address, struct user_regs_struct *regs_struct, mem_loc_t merge_addr) {

  using redmagic::register_t;
  // the dummy values
  assert(write_jump_address != 0xfafafafafafafafa);
  assert(merge_addr != 0xfbfbfbfbfbfbfbfb);

  // that this is a jump with a rel32 term to the next line and is aligned properly
  assert(*(uint8_t*)write_jump_address == 0xE9);
  assert(*(int32_t*)(write_jump_address + 1) == 0);
  assert(((write_jump_address + 1) & 0x3) == 0);

  assert(regs_struct->rsp - TRACE_STACK_OFFSET == (register_t)regs_struct);

  void *ret = NULL;

  auto head = manager->get_tracer_head();
  assert(head->trace_id != nullptr);
  assert(!head->is_temp_disabled);
  assert(manager->branches.find(head->trace_id) != manager->branches.end());
  auto info = &manager->branches[head->trace_id];

#ifdef CONF_GLOBAL_ABORT
  if(global_abort()) {
    //head->did_abort = true;
    // manager->pop_tracer_stack();
    head->is_compiled = head->is_traced = false;
    *((register_t*)(regs_struct->rsp - TRACE_RESUME_ADDRESS_OFFSET)) = (register_t)target_rip;
    return;
  }
#endif

  // remove the free tracer
  // TODO: make this into an actual linked list so that we can keep these tracers around and reuse?
  // TODO: GC the tracers then
  Tracer *l = free_tracer_list.exchange(nullptr);
  if(l == nullptr) {
    // we did not get a tracer, there must not have been one
    // TODO: allocate a new tracer
    assert(protected_malloc);
    protected_malloc = false;
    l = new Tracer(CodeBuffer::CreateBuffer(1024 * 1024));
    protected_malloc = true;
    //assert(0);
  }
  mem_loc_t old_tracing_from = l->tracing_from.exchange(target_rip);
  assert(old_tracing_from == 0);

  assert(head->tracer == nullptr);
  assert(info->tracer == nullptr);
  info->tracer = head->tracer = l;

  info->sub_branches++;

  head->is_compiled = false;

  l->owning_thread = manager->get_thread_id();
  // vvv this might be "wrong" since the frame id might have changed within a given trace
  // but this field is write only atm so might not be a problem
  l->owning_frame_id = branchable_frame_id;

  // calling Start will invalidate the previous stack
  ret = l->Start((void*)target_rip);
  l->set_where_to_patch((int32_t*)(write_jump_address + 1));
  l->set_merge_target(merge_addr);

  assert(ret != NULL);

#ifdef CONF_VERBOSE
  red_printf("======================\nresume trace: %#016lx %#016lx\n", target_rip, head->trace_id);
#endif

  // set the address to jump to
  *((register_t*)(regs_struct->rsp - TRACE_RESUME_ADDRESS_OFFSET)) = (register_t)ret;
}

extern "C" void red_set_temp_resume(void *resume_addr) {
  auto head = manager->get_tracer_head();
  assert(head->resume_addr == nullptr);
  head->resume_addr = resume_addr;
  head->is_temp_disabled = true;
  auto new_head = manager->push_tracer_stack();
  new_head->return_to_trace_when_done = true;
}

extern "C" void* red_end_trace(mem_loc_t normal_end_address, mem_loc_t stack_ptr) {
  // return the address that we want to jump to
  auto head = manager->pop_tracer_stack();
  auto new_head = manager->get_tracer_head();
  assert(head.is_traced);
  assert(head.frame_stack_ptr != -1);
  auto info = &manager->branches[head.trace_id];
  info->count_fellthrough++;
  void *ret = (void*)normal_end_address;
  ((mem_loc_t*)stack_ptr)[-1] = head.frame_stack_ptr - stack_ptr;
  if(new_head->is_traced) {
    if(new_head->tracer) {
      new_head->tracer->JumpFromNestedLoop((void*)normal_end_address);
    }
    if(new_head->resume_addr) {
      assert(head.return_to_trace_when_done);
      ret = new_head->resume_addr;
      new_head->resume_addr = nullptr;
    } else {
#ifdef CONF_GLOBAL_ABORT
      assert(!global_abort() || ret == (void*)normal_end_address);
#endif
    }
  }
#ifdef CONF_VERBOSE
  red_printf("exiting trace %#016lx\n", head.trace_id);
#endif
  return ret;
}

extern "C" void red_end_trace_ensure() {
  auto head = manager->get_tracer_head();
  assert(head->is_traced);
  head->is_traced = false;
  head->is_compiled = false;
  assert(!head->resume_addr);
  assert(!head->tracer);
#ifdef CONF_VERBOSE
  red_printf("exiting trace ensure %#016lx\n", head->trace_id);
#endif
}

extern "C" void* red_branch_to_sub_trace(void *resume_addr, void *sub_trace_id, void* target_rip, mem_loc_t stack_ptr) {
  auto head = manager->get_tracer_head();
  assert(head->is_traced);
  assert(!head->tracer);
  assert(head->resume_addr == nullptr);
  head->resume_addr = resume_addr;
  assert(sub_trace_id != head->trace_id || head->frame_id != branchable_frame_id);

  protected_malloc = false;
  void *ret = manager->backwards_branch(sub_trace_id, target_rip, (void**)stack_ptr);
  protected_malloc = true;
  auto new_head = manager->get_tracer_head();
  new_head->return_to_trace_when_done = true;
  return ret;
}

extern "C" void red_asm_start_tracing(void*, void*, void*, void*);
extern "C" void red_asm_begin_block();
void* Tracer::Start(void *start_addr) {

  set_pc((mem_loc_t)start_addr);

  using namespace asmjit;
  SimpleCompiler compiler(buffer);
  // stash the values of the register that we are about to override
  compiler.mov(x86::ptr(x86::rsp, static_cast<int32_t>(-TRACE_STACK_OFFSET - sizeof(struct user_regs_struct))), x86::rdx);
  compiler.mov(x86::ptr(x86::rsp, static_cast<int32_t>(-TRACE_STACK_OFFSET - sizeof(struct user_regs_struct) - sizeof(register_t))), x86::rsi);
  compiler.mov(x86::ptr(x86::rsp, static_cast<int32_t>(-TRACE_STACK_OFFSET - sizeof(struct user_regs_struct) - 2*sizeof(register_t))), x86::rdi);


  compiler.mov(x86::rdx, imm_ptr(this)); // argument 3
  compiler.mov(x86::rsi, imm_ptr(&red_begin_tracing));

  mem_loc_t stack_ptr = (((mem_loc_t)stack_) + sizeof(stack_)) & ~63;

  resume_struct = {0};
  resume_struct.stack_pointer = (register_t)stack_ptr - sizeof(mem_loc_t);
  *(void**)(stack_ptr - sizeof(mem_loc_t)) = (void*)&red_asm_begin_block;

  compiler.jmp(imm_ptr(interrupt_block_location));
  compiler.mov(x86::r15, imm_u(0xdeadbeef));
  compiler.mov(x86::r15, imm_ptr(start_addr));

  auto written = compiler.finalize();

  trace_start_location = buffer->getRawBuffer() + buffer->getOffset();

  {
    SimpleCompiler compiler2(buffer);
    trace_loop_counter = compiler2.MakeCounter();
  }

  icount = 0;
  last_call_instruction = -1;
#ifdef CONF_ATTEMPT_FORWARD_JUMP_INLINE
  last_local_jump = 0;
  local_jump_min_addr = 0;
#endif

  current_not_traced_call_addr = 0;
  current_not_traced_call_ret_loc = nullptr;


#ifdef CONF_GLOBAL_ABORT
#ifdef NDEBUG
#error "global abort without debug?"
#endif
  // if(global_abort()) {
  //   // disable this tracing

  //   SimpleCompiler compiler2(buffer);
  //   compiler2.jmp(imm_ptr(start_addr));

  //   did_abort = true;
  //   manager->get_tracer_head()->did_abort = true;
  //   CodeBuffer::Relase(buffer);
  //   buffer = nullptr;
  //   assert(0);
  //   return start_addr;
  // }
#endif

  return (void*)written.getRawBuffer();
}

// abort after some number of instructions to see if there is an error with the first n instructions
// useful for bisecting which instruction is failing if there is an error
//#define ABORT_BEFORE 50


#ifndef NDEBUG
bool Tracer::debug_check_abort() {
  // check specific conditions for performing an abort during debugging
  // and if meet, return true
#ifdef ABORT_BEFORE
  if(icount >= ABORT_BEFORE)
    return true;
#endif
#ifdef CONF_GLOBAL_ABORT
  if(global_abort())
    return true;
#endif

  return false;
}
#endif

void Tracer::Run(struct user_regs_struct *other_stack) {
  regs_struct = other_stack;

  regs_struct->rdx = ((register_t*)(regs_struct - 1))[0];
  regs_struct->rsi = ((register_t*)(regs_struct - 1))[-1];
  regs_struct->rdi = ((register_t*)(regs_struct - 1))[-2];


  current_location = udis_loc;


#ifdef CONF_VERBOSE
  red_printf("----->start %i\n", ++loop_n);
#endif

  assert(method_stack.size() == 1);
  assert(method_stack.back().return_stack_pointer == -1);

  run_starting_stack_pointer = regs_struct->rsp;

  if(get_pc() == (mem_loc_t)&red_asm_jump_rsi_resume_trace) {
    // this is only when resuming a tracer after another one exited
    assert(regs_struct->rdi < 250); // this is the offset for the starting stack pointer (not a "real" assert, just some attempt at sanity)
    // we offset the starting stack pointer since that controls where we end up merging back to
    run_starting_stack_pointer += regs_struct->rdi;
    assert(merge_resume != 0);
  }

  while(true) {
    assert(before_stack == 0xdeadbeef);
    assert(after_stack == 0xdeadbeef);
    generated_location = buffer->getRawBuffer() + buffer->getOffset();
    last_location = udis_loc;
#ifdef CONF_ATTEMPT_FORWARD_JUMP_INLINE
    local_jump_min_addr = last_local_jump = 0;
#endif
    assert(current_location == last_location);
    assert(protected_malloc);
    //assert(generation_lock.owns_lock());

//     assert(method_sp_stack.back() >= regs_struct->rsp + move_stack_by);
//     assert(method_sp_stack.size() == method_address_stack.size() + 1);
// #ifdef CONF_MERGE_BACK_ON_RET
//     assert(merge_block_stack.size() > method_address_stack.size());
// #endif

    assert(method_stack.back().return_stack_pointer >= regs_struct->rsp + move_stack_by);
#ifdef CONF_MERGE_BACK_ON_RET
    assert(merge_block_stack.size() >= method_stack.size());
    assert(merge_block_stack.size() >= method_stack.back().corresponding_merge_block);
#endif

    // if we somehow have less then 1kb free then we might have overwritten something
    // which is why this is asserted as an error
    assert(buffer->getFree() > 1024);
    if(buffer->getFree() <= 10 * 1024 && icount - last_call_instruction > 5) {
      // there is less than 10 kb of space on this buffer, so we are going to make a new one
      // disabling malloc protecting might be bad...
      protected_malloc = false;
#ifdef CONF_VERBOSE
      red_printf("switching code generation buffer\n");
#endif
      auto new_buffer = CodeBuffer::CreateBuffer(1024 * 1024);
      {
        SimpleCompiler compiler(new_buffer);
        compiler.mov(asmjit::x86::r15, asmjit::imm_u(0xdeadcafe1));
        compiler.mov(asmjit::x86::r15, asmjit::imm_u(generated_location));
      }
      auto new_gen_l = new_buffer->getRawBuffer() + new_buffer->getOffset();
      {
        SimpleCompiler compiler(buffer);
        compiler.jmp(asmjit::imm_ptr(new_gen_l));
        auto written = compiler.finalize();
      }
      CodeBuffer::Release(buffer);
      buffer = new_buffer;
      generated_location = new_gen_l;
      protected_malloc = true;

    }

  processes_instructions:
    while(ud_disassemble(&disassm)) {

      assert(merge_block_stack.size());

      ++icount;
      ++global_icount;


#ifdef CONF_VERBOSE
      Dl_info dlinfo;
      auto ins_loc = ud_insn_off(&disassm);
      dladdr((void*)ins_loc, &dlinfo);

      if(dlinfo.dli_sname != nullptr)
        red_printf("[%10lu %8i %#016lx] \t%-38s %-20s %s\n", global_icount, icount, ins_loc, ud_insn_asm(&disassm), ud_insn_hex(&disassm), dlinfo.dli_sname);
      else
        red_printf("[%10lu %8i %#016lx] \t%-38s %-20s lib=%s\n", global_icount, icount, ins_loc, ud_insn_asm(&disassm), ud_insn_hex(&disassm), dlinfo.dli_fname);
#endif

#ifndef NDEBUG
      if(global_debugger_int == global_icount) {
        __asm__("int3\n");
      }
#endif

      jmp_info = decode_instruction();
      if(jmp_info.is_jump) {
        if(jmp_info.is_local_jump) {
          // there is a chance that we can directly inline this if this is a short loop
          assert(jmp_info.local_jump_offset);
          if(jmp_info.local_jump_offset < 0) {
#ifdef CONF_ATTEMPT_BACKWARDS_JUMP_INLINE
            if(udis_loc - current_location  > -jmp_info.local_jump_offset) {
              // this is a backwards branch that is going an acceptable distance
              goto instruction_approved;
            }
#endif
          } else {
#ifdef CONF_ATTEMPT_FORWARD_JUMP_INLINE
            // this is a forward branch
            // TODO: there is some bug in this part of code....not sure what it is
            // when running with max foward distance of 512 and starting ipython it will end up crashing
            // when tracing PyInt_AsSsize_t
            // use the bisect tool to find where exactly it is crashing
            if(jmp_info.local_jump_offset > 100)
              // this is too far forward, we are unlikely to actually be able to inline this, so just run it
              goto run_instructions;
            if(last_local_jump == 0) {
              // this is the earliest instruction we are currently aware of so store its address
              last_local_jump = ud_insn_off(&disassm);
            }
            if(udis_loc + jmp_info.local_jump_offset > local_jump_min_addr)
              local_jump_min_addr = udis_loc + jmp_info.local_jump_offset;
            goto instruction_approved;
#endif
          }
        }
        goto run_instructions;
      }

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
#ifndef NDEBUG
      if(debug_check_abort())
        goto run_instructions;
#endif
    instruction_approved:
      last_location = udis_loc;
#ifdef CONF_ATTEMPT_FORWARD_JUMP_INLINE
      if(local_jump_min_addr && udis_loc > local_jump_min_addr) {
        // yay, we are able to direclty inline this jump
        local_jump_min_addr = last_local_jump = 0;
      }
#endif
    }
  run_instructions:
#ifdef CONF_ATTEMPT_FORWARD_JUMP_INLINE
    if(local_jump_min_addr > last_location) {
      // we failed to get far enough in the decoding to allow these jumps to be inlined
      // so we revert back to the last "good" state
      last_location = last_local_jump;
      set_pc(last_local_jump);
      ud_disassemble(&disassm);
      // these jumps can't reference registers so if that is what caused the break then set to false
      rip_used = false;
    }
    //last_local_jump = local_jump_min_addr = 0;
#endif
    if(current_location != last_location) {
      {
        CodeBuffer ins_set(current_location, last_location - current_location);
        buffer->writeToEnd(ins_set);
      }

      current_location = last_location;
      write_interrupt_block();
      continue_program(generated_location);
    }
#ifndef NDEBUG
    if(debug_check_abort())
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

extern "C" void red_asm_end_trace();

void* Tracer::EndTraceFallthrough(bool check_id) {
  assert(current_not_traced_call_addr == (mem_loc_t)&redmagic_fellthrough_branch ||
         current_not_traced_call_addr == (mem_loc_t)&redmagic_force_end_trace);
  current_not_traced_call_addr = 0;
  assert(icount - last_call_instruction < 2);
#ifdef CONF_VERBOSE
  red_printf("tracer end fallthrough\n");
#endif

  auto head = manager->get_tracer_head();
  auto info = &manager->branches[head->trace_id];
  info->traced_instruction_count += icount;
  info->finish_traces++;
  if(info->longest_trace_instruction_count < icount)
    info->longest_trace_instruction_count = icount;

  buffer->setOffset(last_call_generated_op);
  SimpleCompiler compiler(buffer);
  // check that the fallthrough option is actually this trace
  auto rlabel = compiler.newLabel();
  CodeBuffer wb;
  if(check_id) {
    wb = compiler.TestRegister(last_call_pc, RDI, (register_t)head->trace_id, &merge_block_stack.back());
    compiler.restore_registers();
  }
  // have to ignore this ^ now since we are going to be clobbering this register
  compiler.bind(rlabel);
  compiler.mov(asmjit::x86::rdi, asmjit::imm_u(last_call_ret_addr));
  compiler.jmp(asmjit::imm_ptr(&red_asm_end_trace));
  auto w = compiler.finalize();
  if(check_id) {
    wb.replace_stump<uint64_t>(0xfafafafafafafafa, w.getRawBuffer());
  }
#ifdef CONF_MERGE_BACK_ON_RET
  assert(merge_block_stack.size() == method_stack.size());
#else
  assert(merge_block_stack.size() == 1);
#endif
  merge_resume = 0;
  for(auto merge_block : merge_block_stack) {
    mem_loc_t write_addr = merge_block.merge_head;
    while(write_addr != 0) {
      mem_loc_t next_addr = *(mem_loc_t*)write_addr;
      *(mem_loc_t*)write_addr = 0;
      write_addr = next_addr;
    }
  }
  merge_block_stack.clear();
  merge_block_stack.push_back(tracer_merge_block_stack_s());
  method_stack.clear();
  method_stack.push_back(tracer_method_stack_s(0, -1));
  finish_patch();
  tracing_from = 0;
  return (uint8_t*)w.getRawBuffer() + compiler.getLabelOffset(rlabel);
}

void* Tracer::EndTraceLoop() {
  // assert that we recently performed a call
  // this should be to ourselves to end the trace
  assert(current_not_traced_call_addr == (mem_loc_t)&redmagic_backwards_branch);
  current_not_traced_call_addr = 0;
  assert(icount - last_call_instruction < 2);
#ifdef CONF_VERBOSE
  red_printf("tracer end loop back\n");
#endif

  auto head = manager->get_tracer_head();
  auto info = &manager->branches[head->trace_id];
  mem_loc_t loop_location = (mem_loc_t)info->starting_point;
  assert(loop_location);
  info->traced_instruction_count += icount;
  info->finish_traces++;
  if(info->longest_trace_instruction_count < icount)
    info->longest_trace_instruction_count = icount;

  buffer->setOffset(last_call_generated_op);
  SimpleCompiler compiler(buffer);
  // check that we are still backwards branching on the correct trace
  auto wb = compiler.TestRegister(last_call_pc, RDI, (register_t)head->trace_id, &merge_block_stack.back());
  compiler.restore_registers();
  compiler.jmp(asmjit::imm_ptr(loop_location));
  auto written = compiler.finalize();
  wb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());
  assert(merge_block_stack.size() == 1);
  assert(method_stack.size() == 1);
  assert(merge_resume == 0);
  mem_loc_t write_addr = merge_block_stack[0].merge_head;
  merge_block_stack[0] = tracer_merge_block_stack_s();
  merge_resume = 0;
  while(write_addr != 0) {
    mem_loc_t next_addr = *(mem_loc_t*)write_addr;
    *(mem_loc_t*)write_addr = 0;
    write_addr = next_addr;
  }
  method_stack.clear();
  method_stack.push_back(tracer_method_stack_s(0, -1));
  finish_patch();
  tracing_from = 0;
  return (void*)loop_location;
}

void* Tracer::CheckNotSelfFellthrough() {
  assert(current_not_traced_call_addr == (mem_loc_t)&redmagic_fellthrough_branch);
  current_not_traced_call_addr = 0;
  assert(icount - last_call_instruction < 2);

  auto head = manager->get_tracer_head();
  buffer->setOffset(last_call_generated_op);
  SimpleCompiler compiler(buffer);
  auto wb = compiler.TestRegister(last_call_pc, RDI, (register_t)head->trace_id, &merge_block_stack.back(), asmjit::kX86InstIdJe);
  auto w = compiler.finalize();
  wb.replace_stump<uint64_t>(0xfafafafafafafafa, w.getRawBuffer());
  write_interrupt_block();

  return (uint8_t*)w.getRawBuffer() + w.getOffset();
}

void* Tracer::EndTraceEndBranchable() {
  assert(current_not_traced_call_addr == (mem_loc_t)&redmagic_end_branchable_frame);
  current_not_traced_call_addr = 0;
  assert(icount - last_call_instruction < 2);

  // set it such that the next tracer that resumes will also hit the end branchable method
  // this will keep repeating until all the tracers in this frame have fallen
  last_call_ret_addr = last_call_pc;

  // to get around the assert
  current_not_traced_call_addr = (mem_loc_t)&redmagic_fellthrough_branch;
  return EndTraceFallthrough(false);
}

void* Tracer::EndTraceEnsure() {
  if(current_not_traced_call_addr != (mem_loc_t)&redmagic_ensure_not_traced) {
    // then this is probably inside some not trace method block
    // which is fine I guess
    return NULL;
  }
  current_not_traced_call_addr = 0;
  assert(icount - last_call_instruction < 2);

#ifdef CONF_VERBOSE
  red_printf("tracer end ensure\n");
#endif


  auto head = manager->get_tracer_head();
  auto info = &manager->branches[head->trace_id];
  info->traced_instruction_count += icount;
  info->finish_traces++;
  if(info->longest_trace_instruction_count < icount)
    info->longest_trace_instruction_count = icount;

  buffer->setOffset(last_call_generated_op);
  SimpleCompiler compiler(buffer);
  compiler.call(asmjit::imm_ptr(&red_end_trace_ensure));
  compiler.jmp(asmjit::imm_ptr(last_call_ret_addr));
  auto w = compiler.finalize();

  merge_resume = 0;
  for(auto merge_block : merge_block_stack) {
    mem_loc_t write_addr = merge_block.merge_head;
    while(write_addr != 0) {
      mem_loc_t next_addr = *(mem_loc_t*)write_addr;
      *(mem_loc_t*)write_addr = 0;
      write_addr = next_addr;
    }
  }
  merge_block_stack.clear();
  merge_block_stack.push_back(tracer_merge_block_stack_s());
  method_stack.clear();
  method_stack.push_back(tracer_method_stack_s(0, -1));

  finish_patch();
  tracing_from = 0;

  return (void*)w.getRawBuffer();
}



void* Tracer::TempDisableTrace() {
  if(current_not_traced_call_addr != (mem_loc_t)&redmagic_temp_disable) {
    // then this must be inside of some not traced call
    // but we still have to behave the same
    auto head = manager->get_tracer_head();
    head->is_temp_disabled = true;
    assert(head->resume_addr == nullptr);
    manager->push_tracer_stack();
    return NULL;
  }
  //assert(current_not_traced_call_addr == (mem_loc_t)&redmagic_temp_disable);
  assert(icount - last_call_instruction < 2);
  buffer->setOffset(last_call_generated_op);
  SimpleCompiler compiler(buffer);
  auto label = compiler.newLabel();
  compiler.lea(asmjit::x86::rdi, asmjit::x86::ptr(label));
  compiler.call(asmjit::imm_ptr(&red_set_temp_resume));
  compiler.jmp(asmjit::imm_ptr(last_call_ret_addr));
  compiler.mov(asmjit::x86::r15, asmjit::imm_u(0xdeadcafe2));
  compiler.bind(label);
  auto written = compiler.finalize();
  write_interrupt_block();

  red_set_temp_resume((void*)(written.getRawBuffer() + written.getOffset()));

  return (void*)last_call_ret_addr;
}

void Tracer::TempEnableTrace(void *resume_pc) {
  // check that the temp enable instruction is coming in at a expected spot, otherwise fork a new trace
  set_pc((mem_loc_t)resume_pc);
  SimpleCompiler compiler(buffer);
  // the "normal" return address will be set to ris when this returns from the temp disabled region
  auto wb = compiler.TestRegister((mem_loc_t)&red_asm_jump_rsi_temp_enable, RSI, (register_t)resume_pc, &merge_block_stack.back());
  auto written = compiler.finalize();
  wb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());
  write_interrupt_block();
}

void Tracer::JumpFromNestedLoop(void *resume_pc) {
  // this code is very similar to the above, todo:? make into function
  // TempEnableTrace(resume_pc);
  set_pc((mem_loc_t)resume_pc);
  SimpleCompiler compiler(buffer);
  // the "normal" return address will be set to ris when this returns from the temp disabled region
  auto wb = compiler.TestRegister((mem_loc_t)&red_asm_jump_rsi_resume_trace, RSI, (register_t)resume_pc, &merge_block_stack.back());
  auto written = compiler.finalize();
  wb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());
  write_interrupt_block();
}

extern "C" void red_asm_start_nested_trace();

void Tracer::JumpToNestedLoop(void *nested_trace_id) {
  // there should have been a backwards branch instruction that we are going to replace
  assert(icount - last_call_instruction < 2);
  buffer->setOffset(last_call_generated_op);
  SimpleCompiler compiler(buffer);
  compiler.mov(asmjit::x86::rdi, asmjit::imm_u(0xfafafafafafafafa));
  compiler.mov(asmjit::x86::rsi, asmjit::imm_ptr(nested_trace_id));
  compiler.mov(asmjit::x86::rdx, asmjit::imm_u(last_call_ret_addr));
  compiler.jmp(asmjit::imm_ptr(&red_asm_start_nested_trace));
  auto written = compiler.finalize();
  write_interrupt_block();

  mem_loc_t resume_addr = written.getRawBuffer() + written.getOffset();

  manager->get_tracer_head()->resume_addr = (void*)resume_addr;

  written.replace_stump<uint64_t>(0xfafafafafafafafa, resume_addr);
}

void* Tracer::ReplaceIsTracedCall() {
  // if this wasn't the most recent call then don't delete
  // also returning null will make this statement behave in a false way
  if(current_not_traced_call_addr != (mem_loc_t)&redmagic_is_traced)
    return NULL;
  assert(icount - last_call_instruction < 2);
  buffer->setOffset(last_call_generated_op);
  SimpleCompiler compiler(buffer);
  compiler.mov(asmjit::x86::rax, asmjit::imm(1));
  auto written = compiler.finalize();
  write_interrupt_block();

  mem_loc_t resume_addr = written.getRawBuffer() + written.getOffset();

  return (void*)resume_addr;
}

void* Tracer::BeginMergeBlock() {
  // if this method is called from some context where it wasn't inlined in the code
  // then that means that it must have been some other non inlined method which means that we do not
  // want to perform any actions
  if(current_not_traced_call_addr != (mem_loc_t)&redmagic_begin_merge_block)
    return NULL;
  assert(icount - last_call_instruction < 2);
  buffer->setOffset(last_call_generated_op);
  mem_loc_t ret = buffer->getRawBuffer() + buffer->getOffset();
  // there are no instructions to generate for this
  write_interrupt_block();
  merge_block_stack.push_back(tracer_merge_block_stack_s());
  return (void*)ret;
}

void* Tracer::EndMergeBlock() {
  if(current_not_traced_call_addr != (mem_loc_t)&redmagic_end_merge_block)
    return NULL; // see above
  assert(icount - last_call_instruction < 2);
  buffer->setOffset(last_call_generated_op);
  mem_loc_t res_addr = buffer->getRawBuffer() + buffer->getOffset();
  write_interrupt_block();
  mem_loc_t ret = merge_close_core();
  if(ret == 0) {
    ret = res_addr;
  } else {
    Tracer *expected = nullptr;
    if(!free_tracer_list.compare_exchange_strong(expected, this)) {
      // gaaaa
      protected_malloc = false;
      delete this;
      protected_malloc = true;
    }
  }

  return (void*)ret;
}

// calling method has to free tracer if result is non zero
mem_loc_t Tracer::merge_close_core() {
#ifdef CONF_CHECK_MERGE_RIP
  mem_loc_t check_rip;
  if(current_not_traced_call_ret_loc != nullptr) {
    check_rip = last_call_pc;
  } else {
    check_rip = udis_loc;
  }
#endif

  if(merge_block_stack.size() == 1) {
    assert(merge_resume != 0);
    mem_loc_t resume_a = merge_resume;
    merge_resume = 0;
    SimpleCompiler compiler(buffer);
    compiler.jmp(asmjit::imm_ptr(resume_a));
    compiler.mov(asmjit::x86::r15, asmjit::imm_u(0xdeadbeef3));
    compiler.finalize();
    mem_loc_t write_addr = merge_block_stack[0].merge_head;
    merge_block_stack[0] = tracer_merge_block_stack_s();
    // write the parent's jump address
    while(write_addr != 0) {
      mem_loc_t next_addr = *(mem_loc_t*)write_addr;
      *(mem_loc_t*)write_addr = resume_a;
      write_addr = next_addr;
    }
#ifdef CONF_CHECK_MERGE_RIP
    auto merge_f = manager->merge_rip.find(resume_a);
    assert(merge_f != manager->merge_rip.end());
    assert(merge_f->second.find(check_rip) != merge_f->second.end());
    // mem_loc_t merge_rip = merge_f->second;
    // assert(merge_rip == check_rip);
#endif

    // the ending of this tracer instructions
    finish_patch();
    tracing_from = 0;
    merge_resume = 0;
    method_stack.clear();
    method_stack.push_back(tracer_method_stack_s(0,-1));

    // stuff usually done by manager....TODO: converge to a single method
    auto head = manager->get_tracer_head();
    assert(!head->is_compiled);
    assert(head->is_traced);
    assert(head->tracer == this);
    assert(head->trace_id);
    auto info = &manager->branches[head->trace_id];
    assert(info->tracer == this);
    head->tracer = info->tracer = nullptr;
    head->is_compiled = true;
    info->traced_instruction_count += icount;
    if(info->longest_trace_instruction_count < icount)
      info->longest_trace_instruction_count = icount;

    // auto head = manger->get_tracer_head();
    // assert(head->trace_id);
    // assert(head->tracer == this);
    // assert(info->tracer == this);
    // auto info = manager->branches[head->trace_id];
    // head->tracer = info->tracer = nullptr;

    // have to free this tracer
    // Tracer *expected = nullptr;
    // if(!free_tracer_list.compare_exchange_strong(expected, this)) {
    //   // gaaaa
    //   protected_malloc = false;
    //   delete this;
    //   protected_malloc = true;
    // }

#ifdef CONF_VERBOSE
    red_printf("merge block closing back to parent: %#016lx\n", head->trace_id);
#endif

    return resume_a;
  } else {
    mem_loc_t merge_addr = buffer->getRawBuffer() + buffer->getOffset();
    mem_loc_t write_addr = merge_block_stack.back().merge_head;

#ifdef CONF_CHECK_MERGE_RIP
    // if(manager->merge_rip.find(merge_addr) == manager->merge_rip.end() || current_not_traced_call_ret_loc != nullptr)
    //   manager->merge_rip[merge_addr] = check_rip;
    if(write_addr != 0) {
      auto merge_set = &manager->merge_rip[merge_addr];
      merge_set->insert(check_rip);
      assert(merge_set->size() < 3); // just trying to avoid filling the set with a lot of items since this is suppose to catch bugs
    }
#endif

    merge_block_stack.pop_back();
    while(write_addr != 0) {
      mem_loc_t next_addr = *(mem_loc_t*)write_addr;
      *(mem_loc_t*)write_addr = merge_addr;
      write_addr = next_addr;
    }
    return 0;
  }
  assert(0);
}

namespace { void _nonamef() {} }

void* Tracer::DeleteLastCall(void *method) {
  if((mem_loc_t)method != current_not_traced_call_addr)
    return NULL; // this is some other method so just ignore this action
  assert((current_not_traced_call_addr & ~0xffffffffL) == (((mem_loc_t)&_nonamef) & ~0xffffffffL));
  assert(icount - last_call_instruction < 2);
  buffer->setOffset(last_call_generated_op);
  mem_loc_t ret = buffer->getRawBuffer() + buffer->getOffset();
  write_interrupt_block();
  return (void*)ret;
}


void Tracer::finish_patch() {
  if(finish_patch_addr != nullptr) {
    mem_loc_t irip = ((mem_loc_t)finish_patch_addr) + 4;
    int64_t dl = trace_start_location - irip;
    int32_t d = dl;
    assert(d == dl);
    assert(*finish_patch_addr == 0);
    // check that there wasn't a previous tracer that did this
    // TODO: concurrent blocking on these events
    *finish_patch_addr = d;
    finish_patch_addr = nullptr;
  }
}

extern "C" void* red_asm_resume_eval_block(void*, void*);

void Tracer::continue_program(mem_loc_t resume_loc) {
#ifdef CONF_VERBOSE
  red_printf("==> %#016lx\n", resume_loc);
#endif
  assert(regs_struct->rsp - TRACE_STACK_OFFSET == (register_t)regs_struct);
  regs_struct->rsp += move_stack_by;
  move_stack_by = 0;
  *((register_t*)(regs_struct->rsp - TRACE_RESUME_ADDRESS_OFFSET)) = resume_loc;
  // assert((regs_struct->rax & ~0xff) != 0xfbfbfbfbfbfbfb00);
  regs_struct = (struct user_regs_struct*)red_asm_resume_eval_block(&resume_struct, regs_struct);
  // assert((regs_struct->rax & ~0xff) != 0xfbfbfbfbfbfbfb00);
}


void Tracer::continue_program_end_self(mem_loc_t resume_loc) {
#ifdef CONF_VERBOSE
  red_printf("==> %#016lx (end)\n", resume_loc);
#endif
  struct user_regs_struct *l_regs_struct = regs_struct;


  assert(regs_struct->rsp - TRACE_STACK_OFFSET == (register_t)l_regs_struct);
  l_regs_struct->rsp += move_stack_by;
  move_stack_by = 0;
  *((register_t*)(l_regs_struct->rsp - TRACE_RESUME_ADDRESS_OFFSET)) = resume_loc;

  Tracer *expected = nullptr;
  if(!free_tracer_list.compare_exchange_strong(expected, this)) {
    // gaaaa
    assert(expected != this);
    protected_malloc = false;
    delete this;
    protected_malloc = true;
  }

  // this should not be returning
  red_asm_resume_eval_block(NULL, l_regs_struct);

  assert(0);
  __builtin_unreachable();

  // // assert((regs_struct->rax & ~0xff) != 0xfbfbfbfbfbfbfb00);
  // regs_struct = (struct user_regs_struct*)
  // // assert((regs_struct->rax & ~0xff) != 0xfbfbfbfbfbfbfb00);
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
//ASM_BLOCK(push_stack);
//ASM_BLOCK(call_direct);


void Tracer::write_interrupt_block() {
  // write a block that will return control back to this program
  auto offset = buffer->getOffset();
  // auto written = buffer->writeToEnd(cb_interrupt_block);
  // written.replace_stump<uint64_t>(0xfafafafafafafafa, (uint64_t)&resume_struct);
  {
    // TODO: DON'T USE SimpleCompiler here, it has a high overhead for starting and cleanup
    // will be much faster to just hardcode a jmp with 32 bid address
    SimpleCompiler compiler(buffer);
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
    register_t rv = 0;
    if(ri != -1)
      rv = ((register_t*)regs_struct)[ri];
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

  case UD_Inop: {
    // this is used to remove nop since they are no longer helpful with alignment since we are rewriting everything
    ret.is_jump = true;
    return ret;
  }

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
      ret.local_jump_offset = opr->lval.sbyte;
      break;
    case 16:
      ret.local_jump_offset = opr->lval.sword;
      break;
    case 32:
      ret.local_jump_offset = opr->lval.sdword;
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
      ret.local_jump_offset = opr->lval.sbyte;
      break;
    case 16:
      ret.local_jump_offset = opr->lval.sword;
      break;
    case 32:
      ret.local_jump_offset = opr->lval.sdword;
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
        ret.local_jump_offset = opr->lval.sbyte;
        break;
      case 16:
        ret.local_jump_offset = opr->lval.sword;
        break;
      case 32:
        ret.local_jump_offset = opr->lval.sdword;
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

  case UD_Iint3: {
    // if we find an int3 then this means that there is some debugging statement and we don't want to trace that
    red_printf("found int3 debugging statement, aborting");
    abort();
    return ret;
  }

  case UD_Iinvalid: {
    //cerr << "no idea: " << ud_insn_hex(&disassm) << endl;
    red_printf("no idea: %s\n", ud_insn_hex(&disassm));
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

  // uint8_t true_encoding[4];
  // uint8_t true_encoding_len;

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


// the binary encodings of these instructions with 4 bytes for the jump address
// { 0x0F, 0x80, 0xCD }, 3,
// { 0x0F, 0x81, 0xCD }, 3,
// { 0x0F, 0x82, 0xCD }, 3,
// { 0x0F, 0x83, 0xCD }, 3,
// { 0x0F, 0x84, 0xCD }, 3,
// { 0x0F, 0x85, 0xCD }, 3,
// { 0x0F, 0x86, 0xCD }, 3,
// { 0x0F, 0x87, 0xCD }, 3,
// { 0x0F, 0x88, 0xCD }, 3,
// { 0x0F, 0x89, 0xCD }, 3,
// { 0x0F, 0x8A, 0xCD }, 3,
// { 0x0F, 0x8B, 0xCD }, 3,
// { 0x0F, 0x8C, 0xCD }, 3,
// { 0x0F, 0x8D, 0xCD }, 3,
// { 0x0F, 0x8E, 0xCD }, 3,
// { 0x0F, 0x8F, 0xCD }, 3,


struct conditional_jumps_opts jump_opts[] = {
  { UD_Ijo,   UD_Ijno, 0, eflag_of, 0, 0, 0 },
  { UD_Ijno,  UD_Ijo,  eflag_of, 0, 0, 0, 0 },
  { UD_Ijb,   UD_Ijae, 0, eflag_cf, 0, 0, 0 },
  { UD_Ijae,  UD_Ijb,  eflag_cf, 0, 0, 0, 0 },
  { UD_Ijz,   UD_Ijnz, 0, eflag_zf, 0, 0, 0 },
  { UD_Ijnz,  UD_Ijz,  eflag_zf, 0, 0, 0, 0 },
  { UD_Ijbe,  UD_Ija,  eflag_cf | eflag_zf, 0, 0, 0, 1 },
  { UD_Ija,   UD_Ijbe, eflag_cf | eflag_zf, 0, 0, 0, 0 },
  { UD_Ijs,   UD_Ijns, 0, eflag_sf, 0, 0, 0 },
  { UD_Ijns,  UD_Ijs,  eflag_sf, 0, 0, 0, 0 },
  { UD_Ijp,   UD_Ijnp, 0, eflag_pf, 0, 0, 0 },
  { UD_Ijnp,  UD_Ijp,  eflag_pf, 0, 0, 0, 0 },
  { UD_Ijl,   UD_Ijge, 0, 0, 0, eflag_sf | eflag_of, 0 },
  { UD_Ijge,  UD_Ijl,  0, 0, eflag_sf | eflag_of, 0, 0 },
  { UD_Ijle,  UD_Ijg,  eflag_zf, 0, eflag_sf | eflag_of, 0, 1 },
  { UD_Ijg,   UD_Ijle, eflag_zf, 0, eflag_sf | eflag_of, 0, 0 }
};

void Tracer::evaluate_instruction() {

  enum ud_mnemonic_code mnem = ud_insn_mnemonic(&disassm);

  switch(mnem) {

  case UD_Inop: {
    // does nothing
    return;
  }

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

    SimpleCompiler compiler(buffer);

    auto cb_b = compiler.ConditionalJump(alternate_instructions, AlignedInstructions::get_asm_mnem(emit), &merge_block_stack.back());

    auto written = compiler.finalize();
    cb_b.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());
    return;

    // uint8_t lbuffer[16] = {
    //   0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa,
    //   0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa
    // };

    // uint8_t buffer_used = 0;

    // SimpleCompiler resume_comp(buffer.get());

    // auto resume_cb = compiler.MakeResumeTraceBlock(ud_insn_off(&disassm));
    // auto resume_label = compiler.newLabel();
    // compiler


    // for(int i = 0; i < sizeof(jump_opts); i++) {
    //   if(jump_opts[i].code == emit) {
    //     memcpy(lbuffer, jump_opts[i].true_encoding, jump_opts[i].true_encoding_len);
    //     buffer_used += jump_opts[i].true_encoding_len;

    //     buffer_used += 4; // the relative jump address
    //     CodeBuffer buff((mem_loc_t)&lbuffer, buffer_used);
    //     auto written = buffer->writeToEnd(buff);
    //     // TODO: make written do something to replace to jump address
    //     return;
    //   }
    // }

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
      // the value of opr->index doesn't matter and would not necessarly have been set
      //assert(opr->index == UD_NONE);
      int ri = ud_register_to_sys(opr->base);
      assert(ri != -1);
      register_t rv = ((register_t*)regs_struct)[ri];
      // assert(ri < sizeof(test_register_instructions) / sizeof(group_register_instructions_s));
      // auto written = buffer->writeToEnd(test_register_instructions[ri].instruction);
      // written.replace_stump<uint64_t>(0xfafafafafafafafa, rv);

      SimpleCompiler compiler(buffer);
      auto r_cb = compiler.TestRegister(ud_insn_off(&disassm), ri, rv, &merge_block_stack.back());
      auto written = compiler.finalize();

      r_cb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());

      jump_dest = rv;
    } else if(opr->type == UD_OP_MEM) {
      if(opr->base == UD_R_RIP) {
        // then we are going to assume that this is a constant value since this is relative to the rip
        auto v = get_opr_value(opr);
        mem_loc_t t = *(mem_loc_t*)v.address;
        if(t == udis_loc) {
          // this is what it looks like when there is some dynamic linked library and it is going to resolve its address
          // and the store it in the memory location that we have just read from

          red_printf("=============TODO: jumping to the next line to reolve an address, don't inline\n");
          abort();
        }
        jump_dest = t;
      } else {
        SimpleCompiler compiler(buffer);
        AlignedInstructions ali(&disassm);
        auto v = get_opr_value(opr);
        compiler.add_used_registers(ali.registers_used());
        jump_dest = v.is_ptr ? *v.address_ptr : v.address;
        auto r_cb = compiler.TestOperand(ud_insn_off(&disassm), ali.get_asm_op(0), jump_dest, &merge_block_stack.back());
        auto written = compiler.finalize();
        r_cb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());




        // if(opr->index == UD_NONE) {
        //   int i = ud_register_to_sys(opr->base);
        //   auto v = get_opr_value(opr);
        //   register_t rv = ((register_t*)(regs_struct))[i];
        //   auto r_cb = compiler.TestRegister(ud_insn_off(&disassm), i, rv);
        //   auto written = compiler.finalize();
        //   r_cb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());

        //   jump_dest = *(mem_loc_t*)v.address;
        // } else {
        //   auto v = get_opr_value(opr);
        //   compiler.TestOperand(ud_insn_off(&disassm), ali.get_asm_op(0),
        // }
      }
    }
    else {
      assert(0);
    }

    process_jump_dest:
    assert(jump_dest != 0);
    if(last_call_instruction + 1 == icount) {
      // we are jumping to a method eg dynamically loaded, so change what we think the methods address is
      assert(!method_stack.empty());
      assert(method_stack.back().return_stack_pointer == regs_struct->rsp + move_stack_by);
      method_stack.back().method_address = jump_dest;
    }
    if(!manager->should_trace_method((void*)jump_dest)) {
      mem_loc_t cont_addr;
      if(last_call_instruction + 1 == icount) {
        // then the first operation in this method was a jump, which means that we were probably jumping through a redirect with the dynamic linker
        buffer->setOffset(last_call_generated_op);
        pop_stack();
        method_stack.pop_back(); // have to pop since we aren't inlining this
#ifdef CONF_MERGE_BACK_ON_RET
        mem_loc_t merge_res = merge_close_core();
        assert(merge_res == 0);
#endif
        {
          set_pc(last_call_ret_addr);
          SimpleCompiler compiler(buffer);
          compiler.call(asmjit::imm_ptr(jump_dest));
          auto written = compiler.finalize();
          write_interrupt_block();
          cont_addr = written.getRawBuffer();
        }


        current_not_traced_call_ret_loc = (mem_loc_t*)(regs_struct->rsp + move_stack_by - sizeof(register_t));
        current_not_traced_call_addr = jump_dest;
        continue_program(cont_addr);
        current_not_traced_call_addr = 0;
        current_not_traced_call_ret_loc = nullptr;
        icount++; // this prevents the next instruction if it is a jump from thinking it is the first in a method
        return;

      } else {
        // we are jumping to another method and isn't the first instruction, which means that this is behaving like a tail call optimization
        register_t return_pc = peek_stack();
        set_pc(return_pc);

// #ifdef CONF_MERGE_BACK_ON_RET
//         mem_loc_t merge_close = merge_close_core();
//         assert(merge_close == 0);
//         if(merge_close) {
//           continue_program(merge_close);
//           assert(0);
//         }
// #endif
//         assert(!method_address_stack.empty());
//         assert(method_sp_stack.back() == regs_struct->rsp + move_stack_by);
//         method_address_stack.pop_back();
//         method_sp_stack.pop_back();

        {
          SimpleCompiler compiler(buffer);
          auto call_i = compiler.newLabel();
          // pop the previous return address off the stack
          // this will keep the stack at the same expected level for the next instruction
          // since this local return address will be where this instruction expects to find it
          compiler.add(asmjit::x86::rsp, asmjit::imm(8));
          compiler.bind(call_i);
          compiler.call(asmjit::imm_ptr(jump_dest));
          size_t call_io = compiler.getLabelOffset(call_i);
          last_call_generated_op = buffer->getOffset() + call_io;
          last_call_instruction = icount;
          auto written = compiler.finalize();
          write_interrupt_block();
          cont_addr = written.getRawBuffer();
        }

        current_not_traced_call_ret_loc = (mem_loc_t*)(regs_struct->rsp + move_stack_by - sizeof(register_t));
        current_not_traced_call_addr = jump_dest;
        continue_program(cont_addr);
        current_not_traced_call_addr = 0;
        current_not_traced_call_ret_loc = nullptr;
        icount++; // this prevents the next instruction if it is a jump from thinking it is the first in a method

        assert(method_stack.back().return_stack_pointer >= regs_struct->rsp + move_stack_by - sizeof(register_t));
#ifdef CONF_MERGE_BACK_ON_RET
        if(method_stack.back().return_stack_pointer == -1 ||
           method_stack.back().return_stack_pointer == regs_struct->rsp + move_stack_by - sizeof(register_t)) {
          mem_loc_t merge_close = merge_close_core();
          if(merge_close)
            continue_program_end_self(merge_close);
        }
        assert(merge_block_stack.size() < method_stack.back().corresponding_merge_block || method_stack.back().corresponding_merge_block == 0);
#endif
        if(method_stack.back().return_stack_pointer == regs_struct->rsp + move_stack_by - sizeof(register_t)) {
          assert(!method_stack.empty());
          //assert(method_sp_stack.back() == regs_struct->rsp + move_stack_by - sizeof(register_t));
          method_stack.pop_back();
        }

        return;
      }

      assert(0);
    }

    // if(last_call_instruction + 1 == icount) {
    //   // then the first operation in this method was a jump, which means that we were probably jumping through a redirect with the dynamic linker
    //   if(!manager->should_trace_method((void*)jump_dest)) {
    //     mem_loc_t cont_addr;
    //     {
    //       buffer->setOffset(last_call_generated_op);
    //       pop_stack();
    //       set_pc(last_call_ret_addr);
    //       SimpleCompiler compiler(buffer.get());
    //       compiler.call(asmjit::imm_ptr(jump_dest));
    //       auto written = compiler.finalize();
    //       write_interrupt_block();
    //       cont_addr = written.getRawBuffer();
    //     }
    //     continue_program(cont_addr);
    //     return;
    //   }
    // }
    set_pc(jump_dest);
    return;
  }
  case UD_Icall: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0);
    const ud_operand_t *opr2 = ud_insn_opr(&disassm, 1);
    assert(opr2 == NULL); // not 100% sure what the second opr would be used for

    register_t ret_addr = ud_insn_off(&disassm) + ud_insn_len(&disassm);
    mem_loc_t call_pc = 0;

    last_call_instruction = icount;

    if(opr1->type == UD_OP_IMM || opr1->type == UD_OP_JIMM) {
      if(opr1->type == UD_OP_IMM) {
        switch(opr1->size) {
        case 32:
          call_pc = udis_loc & ~0xffffffff | opr1->lval.udword;
          break;
        default:
          assert(0);
        }
      } else {
        assert(opr1->type == UD_OP_JIMM);
        switch(opr1->size) {
        case 16:
          call_pc = udis_loc + opr1->lval.sword;
          break;
        case 32:
          call_pc = udis_loc + opr1->lval.sdword;
          break;
        default:
          assert(0);
        }
      }
    } else {

      // TODO: check that the register is pointing at the same location in memory
      auto v = get_opr_value(opr1);
      call_pc = v.is_ptr ? *v.address_ptr : v.address;
      if(opr1->base != UD_R_RIP) {
        SimpleCompiler compiler(buffer);
        AlignedInstructions ali(&disassm);
        compiler.add_used_registers(ali.registers_used());
        auto r_cb = compiler.TestOperand(ud_insn_off(&disassm), ali.get_asm_op(0), call_pc, &merge_block_stack.back());
        auto written = compiler.finalize();
        r_cb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());
      }


      // opr_value ta = get_opr_value(opr1);
      // assert(0);
      // if(ta.is_ptr) {
      //   // vtable branching
      //   mem_loc_t value = *ta.address_ptr;
      //   SimpleCompiler compiler(buffer.get());
      //   //compiler.TestRegister(
      //   auto r_cb = compiler.TestMemoryLocation(ud_insn_off(&disassm), ta.address, value);
      //   auto written = compiler.finalize();
      //   r_cb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());
      //   call_pc = value;
      // } else {
      //   assert(!ta.is_ptr);
      //   // then we are branching to the address stored in the register
      //   assert(opr1->index == UD_NONE);
      //   SimpleCompiler compiler(buffer.get());
      //   auto r_cb = compiler.TestRegister(ud_insn_off(&disassm), ud_register_to_sys(opr1->base), ta.value);
      //   auto written = compiler.finalize();
      //   r_cb.replace_stump<uint64_t>(0xfafafafafafafafa, written.getRawBuffer());
      //   call_pc = ta.value;
      // }
    }

    assert(call_pc != 0);

    last_call_generated_op = buffer->getOffset();
    last_call_ret_addr = ret_addr;
    last_call_pc = ud_insn_off(&disassm);

    if(!redmagic::manager->should_trace_method((void*)call_pc)) {
      // check if this is some method that we should avoid inlining
      // auto buf_loc = buffer->getRawBuffer() + buffer->getOffset();
      // auto written = buffer->writeToEnd(cb_asm_call_direct);
      // written.replace_stump<uint64_t>(0xfafafafafafafafa, call_pc);
      mem_loc_t cont_addr;
      {
        SimpleCompiler compiler(buffer);
        compiler.call(asmjit::imm_ptr(call_pc));
        auto cb = compiler.finalize();

        set_pc(ret_addr);

        current_location = udis_loc;
        write_interrupt_block();
        cont_addr = cb.getRawBuffer();
      }
      current_not_traced_call_ret_loc = (mem_loc_t*)(regs_struct->rsp + move_stack_by - sizeof(register_t));
      current_not_traced_call_addr = call_pc;
      continue_program(cont_addr);
      current_not_traced_call_addr = 0;
      current_not_traced_call_ret_loc = nullptr;

      icount++; // this is for the extra "internal" instructions (and prevents jump from thinking that it directly followed a call)
    } else {
      // inline this method, so push the return address and continue
      // auto written = buffer->writeToEnd(cb_asm_push_stack);
      // written.replace_stump<uint64_t>(0xfafafafafafafafa, ret_addr);
      SimpleCompiler compiler(buffer);
      // compiler.mov(asmjit::x86::r15, asmjit::imm(ret_addr));
      // compiler.push(asmjit::imm(ret_addr));
      compiler.Push64bitValue(ret_addr);
      auto w = compiler.finalize();
      push_stack(ret_addr);
      set_pc(call_pc);
      assert(regs_struct->rsp + move_stack_by <= method_stack.back().return_stack_pointer);
      method_stack.push_back(tracer_method_stack_s(call_pc, regs_struct->rsp + move_stack_by));
#ifdef CONF_MERGE_BACK_ON_RET
      merge_block_stack.push_back(tracer_merge_block_stack_s());
      method_stack.back().corresponding_merge_block = merge_block_stack.size();
      merge_block_stack.back().method_merge = true;
#endif
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
#ifndef NDEBUG
    const ud_operand_t *opr = ud_insn_opr(&disassm, 0);
    assert(opr == NULL);
#endif
    // These prefixes are used for alignment purposes and have no impact on the execution of the instruction
    // assert(disassm.pfx_rep == UD_NONE);
    // assert(disassm.pfx_repe == UD_NONE);
    // assert(disassm.pfx_repne == UD_NONE);
    mem_loc_t ret_addr = pop_stack();
    set_pc(ret_addr);
    buffer->writeToEnd(cb_asm_pop_stack);

    assert(method_stack.back().return_stack_pointer >= regs_struct->rsp + move_stack_by - sizeof(register_t));
#ifdef CONF_MERGE_BACK_ON_RET
    assert(merge_block_stack.size() >= method_stack.back().corresponding_merge_block);
    if((method_stack.back().return_stack_pointer == -1 && regs_struct->rsp + move_stack_by - sizeof(register_t) >= run_starting_stack_pointer) ||
       method_stack.back().return_stack_pointer == regs_struct->rsp + move_stack_by - sizeof(register_t)) {
      bool method_merge = merge_block_stack.back().method_merge;
      mem_loc_t merge_close = merge_close_core();
      if(merge_close) {
        // we won't have the info for this merge block since it currently isn't contained on the stack
        continue_program_end_self(merge_close);
      } else {
        assert(method_merge == true);
      }
    }
    //assert(merge_block_stack.size() >= method_stack.back().corresponding_merge_block);// || method_stack.back().corresponding_merge_block == 0);
#endif
    if(method_stack.back().return_stack_pointer == regs_struct->rsp + move_stack_by - sizeof(register_t)) {
      assert(!method_stack.empty());
      //assert(method_sp_stack.back() == regs_struct->rsp + move_stack_by - sizeof(register_t));
      method_stack.pop_back();
    }
    return;
  }

  case UD_Iinvalid: {
    red_printf("no idea: %s\n", ud_insn_hex(&disassm));
    assert(0);
  }

  default: {
    assert(0);
  }
  }

}


void Tracer::replace_rip_instruction() {

  enum ud_mnemonic_code mnem = ud_insn_mnemonic(&disassm);

  AlignedInstructions ali(&disassm);
  uint64_t used_registers = ali.registers_used();


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
      SimpleCompiler compiler(buffer);
      compiler.SetRegister(dest, val.address);
      return;
    }
    assert(0);
  }


    /*... UD_Imovzx:*/
  case UD_Imov:
  case UD_Imovq:
  case UD_Imovsxd:
  case UD_Imovss:
  case UD_Imovsd:
  case UD_Imovhps: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0); // dest address
    const ud_operand_t *opr2 = ud_insn_opr(&disassm, 1); // source address
    assert(opr1 != NULL && opr2 != NULL);
    if(opr2->base == UD_R_RIP && opr2->index == UD_NONE && opr1->type == UD_OP_REG && ali.get_op(0)->register_i.size == 64) {
      // then we are just reading some offset from this address, which is constant
      // also we have a register which we are about to clobber, so we can use it to store the address instead of allocating a new register
      opr_value val = get_opr_value(opr2);
      assert(val.is_ptr);
      // assert(opr1->type == UD_OP_REG);
      int dest = ud_register_to_sys(opr1->base);

      SimpleCompiler compiler(buffer);
      auto r = compiler.get_register(dest);
      compiler.mov(r, asmjit::imm_u(val.address));
      // use the aligned instruction so that the correct size is read from memory
      compiler.emit(ali.get_asm_mnem(), ali.get_asm_op(0), asmjit::x86::ptr(r));

      return;
    }
    // we must be writing to memory instead of the register, which means that we can't use it as a scratch
    // location to store the address, instead just use the auto rewriter
    goto _auto_rewrite_register;
  }

  case UD_Ipush: {
    const ud_operand_t *opr1 = ud_insn_opr(&disassm, 0);
    assert(opr1->index == UD_NONE);
    opr_value val = get_opr_value(opr1);
    assert(val.is_ptr);
    SimpleCompiler compiler(buffer);
    compiler.PushMemoryLocationValue(val.address);
    auto written = compiler.finalize();
    return;
  }

  case UD_Ipop: {
    // will change the stack pointer so have to handle specially
    assert(0);
  }

    //case UD_Ipush: // have to do push independently since the stack is moving
  case UD_Iadd:
  case UD_Isub:
  case UD_Iimul:
  case UD_Icmp:
  case UD_Itest:
  case UD_Ixor:
  case UD_Idec:
  case UD_Iinc:


  case UD_Icmpxchg: // todo: don't want this here....

  _auto_rewrite_register:
    {
      // automatically rewrite the registers that are being used
      // and then use the compiler to generate the approperate bytes
      assert((used_registers & (1 << RIP)) != 0);
      assert((used_registers & (1 << RSP)) == 0);
      used_registers &= ~(1 << RIP);

      SimpleCompiler compiler(buffer);
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
    //AlignedInstructions ali(&disassm);
    // TODO: currently using a whitelist of instructions to check what is fine, but would be better if there was a black list?
    // if there was a blacklist what instructions should go on it?


#ifndef CONF_VERBOSE
    // then nothing would have printed so figure out what to print and print that
    ud_set_syntax(&disassm, UD_SYN_ATT);
    set_pc(ud_insn_off(&disassm));
    // redo the disassemble
    ud_disassemble(&disassm);
    red_printf("[%10lu %8i %#016lx] \t%-38s %-20s %s\n", global_icount, icount, ud_insn_off(&disassm), ud_insn_asm(&disassm), ud_insn_hex(&disassm), "??");
#endif


    red_printf("failed to replace rip instruction\n");


    manager->print_info();

    ::abort();
  }
  }
}


void Tracer::abort() {
  {
    red_printf("\n--ABORT--\n");
    did_abort = true;
    auto head = manager->get_tracer_head();
    head->is_traced = head->is_compiled = false;
    //head->did_abort = true;
    auto info = &manager->branches[head->trace_id];
    assert(info->tracer == this);
    //info->tracer = nullptr;
    //manager->get_tracer_head()->is_traced = false;
    //is_traced = false;

    // // // write a resume block here in case that we want to retry this trace
    // // // then we don't have to redo it from scratch
    // SimpleCompiler compiler(buffer);
    // // auto r_cb = compiler.MakeResumeTraceBlock(current_location);
    // // compiler.jmp(asmjit::imm_ptr(r_cb.getRawBuffer()));
    // compiler.jmp(asmjit::imm_ptr(current_location));
    write_interrupt_block();
    finish_patch();
  }
  //protected_malloc = false;
  mem_loc_t l = current_location;
  while(true) {
    auto head = manager->get_tracer_head();
    head->is_traced = head->is_compiled = false;
    head->tracer = nullptr;
    continue_program(l);
    red_printf("was running an aborted trace\n");
  }


  // did_abort = true;
  // red_printf("\n--ABORT--\n");
  // // hack so we can use the fallthrough
  // last_call_generated_op = buffer->getOffset();
  // last_call_instruction = icount;
  // last_call_ret_addr = last_location;

  // assert(generated_location == last_location);

  // mem_loc_t l = (mem_loc_t)EndTraceFallthrough();
  // continue_program(l);
}


void Tracer::run_debugger() {
  red_printf("\n----ABORT debugger---\n");
  SimpleCompiler compiler(buffer);
  compiler.int3();
  //compiler.hlt();
  compiler.finalize();
  continue_program(current_location);
}

void Tracer::kill_trace() {

  assert(0); // TODO:

}

void Tracer::blacklist_function() {
  assert(!method_stack.empty());
  // blacklist this current method
  manager->do_not_trace_method((void*)method_stack.back().method_address);
  kill_trace();
}
