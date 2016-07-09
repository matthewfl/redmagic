#include "simple_compiler.h"

using namespace redmagic;
using namespace asmjit;

SimpleCompiler::~SimpleCompiler() {
  if(buffer) {
    finalize();
  }
}

CodeBuffer SimpleCompiler::finalize() {
  assert(buffer);
  // check that no one else used this buffer while this was running
  assert(buffer->getRawBuffer() + buffer->getOffset() == buffer_cursor);
  restore_registers();
  getOffset();
  getCodeSize();
  void *start = make();
  assert(start == (void*)buffer_cursor);
  size_t len = runtime.getBaseAddress() - buffer_cursor;
  buffer->setOffset(runtime.getBaseAddress() - buffer->getRawBuffer());

  buffer = NULL;
  CodeBuffer ret(buffer_cursor, len);
  ret.can_write_buffer = true;
  return ret;
}

void SimpleCompiler::restore_registers() {
  uint64_t restore = clobbered_registers;
  int indx = 0;
  while(restore) {
    if(restore & 0x1) {
      mov(get_register_from_id(indx), x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + indx * 8 + move_stack_by));
    }
    restore >>= 1;
    indx++;
  }
  clobbered_registers = 0;
}

void SimpleCompiler::protect_register(int id) {
  if(clobbered_registers & (1 << id) == 0) {
    mov(x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + id * 8 + move_stack_by), get_register_from_id(id));
    clobbered_registers |= 1 << id;
  }
}

const asmjit::X86GpReg& SimpleCompiler::get_scratch_register() {
  int indx = 0;
  if(~regs_using & clobbered_registers) {
    // if there is a clobbered register that we can use as scratch then favor that
    while(indx <= RDI) {
      if((~regs_using & clobbered_registers & (1 << indx)) == 0) {
        regs_using |= 1 << indx;
        return get_register(indx);
      }
    }
  }
  while(indx <= RDI) {
    if((regs_using & (1 << indx)) == 0) {
      protect_register(indx);
      regs_using |= 1 << indx;
      clobbered_registers |= 1 << indx;
      return get_register_from_id(indx);
    }
  }
  // did not find a register
  assert(0);
}

const asmjit::X86GpReg& SimpleCompiler::get_register(int id) {
  assert((clobbered_registers & 1 << id) == 0);
  regs_using |= 1 << id;
  return get_register_from_id(id);
}


void SimpleCompiler::MemToRegister(mem_loc_t mem, int reg) {
  auto r = get_register(reg);
  mov(r, imm_u(mem));
  mov(r, x86::ptr(r));
}

void SimpleCompiler::RegisterToMem(int reg, mem_loc_t mem) {
  auto r = get_register(reg);
  auto scr = get_scratch_register();
  mov(scr, imm_u(mem));
  mov(x86::ptr(scr), r);
}

void SimpleCompiler::SetRegister(int reg, register_t val) {
  mov(get_register(reg), imm_u(val));
}

void SimpleCompiler::TestRegister(int reg, register_t val) {
  auto r = get_register(reg);
  Label success = newLabel();
  pushf();
  test(r, imm_u(val));
  je(success);
  // TODO: make this use some label for a generated address
  popf();
  jmp(imm_u(0xfafafafafafafafa));
  bind(success);
  popf();
}
