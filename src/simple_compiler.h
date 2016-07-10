#ifndef REDMAGIC_ASMJIT_WRAP_H_
#define REDMAGIC_ASMJIT_WRAP_H_

#include "jit_internal.h"
#include "constants.h"
#include "align_udis_asmjit.h"
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

    // stash the register
    void protect_register(int id);
    void restore_registers();
    void move_stack(int amount);

    // argument of which registers it should avoid when allocating a new scratch register
    const asmjit::X86GpReg& get_scratch_register();
    // get the current value of the register
    // should be called first since it will add to protection
    const asmjit::X86GpReg& get_register(int id);

    void add_used_registers(uint64_t regs);

    void MemToRegister(mem_loc_t where, int reg);
    void RegisterToMem(int reg, mem_loc_t where);
    void SetRegister(int reg, register_t val);
    void PushMemoryLocationValue(mem_loc_t where);

    void TestRegister(int reg, register_t val);

    mem_loc_t MakeResumeTraceBlock(mem_loc_t tracer_base_ptr, mem_loc_t resume_pc);

    uint64_t* MakeCounter();

  private:
    CodeBuffer *buffer;
    mem_loc_t buffer_cursor;

    // registers that we have clobbered and thus have to restore at the end
    uint64_t clobbered_registers = 0;
    // registers that our program is using for something
    // so dont reallocate these
    uint64_t regs_using = 0;
    uint32_t trampolines_used = 0;

    int32_t move_stack_by = 0;

    asmjit::StaticRuntime runtime;

    void set_label_address(const asmjit::Label &label, mem_loc_t addr);

  public:
    virtual size_t _relocCode(void *_dst, asmjit::Ptr baseAddress) const noexcept override;

  };

}

#endif // REDMAGIC_ASMJIT_WRAP_H_
