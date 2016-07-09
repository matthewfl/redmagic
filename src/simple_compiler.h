#ifndef REDMAGIC_ASMJIT_WRAP_H_
#define REDMAGIC_ASMJIT_WRAP_H_

#include "jit_internal.h"
#include "constants.h"
#include <asmjit/asmjit.h>

namespace redmagic {
  class SimpleCompiler final : public asmjit::X86Assembler {
  public:
    SimpleCompiler(CodeBuffer *buffer):
      buffer(buffer),
      runtime((void*)(buffer->getRawBuffer() + buffer->getOffset()), buffer->getSize() - buffer->getOffset()),
      //assembler(&runtime),
      buffer_cursor(buffer->getRawBuffer() + buffer->getOffset()),
      asmjit::X86Assembler(&runtime)
    {
    }

    // trigger generating the code to the buffer;
    ~SimpleCompiler();
    CodeBuffer finalize();

    // asmjit::X86Assembler assembler;

    auto& get_register_from_id(int id) {
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

    // stash the register
    void protect_register(int id);
    void restore_registers();
    void move_stack(int amount);

    // argument of which registers it should avoid when allocating a new scratch register
    const asmjit::X86GpReg& get_scratch_register();
    // get the current value of the register
    // should be called first since it will add to protection
    const asmjit::X86GpReg& get_register(int id);

    void MemToRegister(mem_loc_t where, int reg);
    void RegisterToMem(int reg, mem_loc_t where);
    void SetRegister(int reg, register_t val);

    void TestRegister(int reg, register_t val);

  private:
    CodeBuffer *buffer;
    mem_loc_t buffer_cursor;

    // registers that we have clobbered and thus have to restore at the end
    uint64_t clobbered_registers = 0;
    // registers that our program is using for something
    // so dont reallocate these
    uint64_t regs_using = 0;;

    int32_t move_stack_by = 0;

    asmjit::StaticRuntime runtime;

  };

}

#endif // REDMAGIC_ASMJIT_WRAP_H_
