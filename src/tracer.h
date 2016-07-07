#ifndef REDMAGIC_TRACER_H_
#define REDMAGIC_TRACER_H_
#include "jit_internal.h"

namespace redmagic {

  struct jump_instruction_info;

#define TRACE_STACK_OFFSET 728  /* hardcode offset from this base stack */

  class Tracer {
  public:
    Tracer(std::shared_ptr<CodeBuffer> buffer);

    void Start();

    inline mem_loc_t _get_udis_location() { return udis_loc++; }

    void Run(void *);
  private:


    void set_pc(uint64_t);

    struct jump_instruction_info decode_instruction();
    void evaluate_instruction();

    void continue_program(mem_loc_t);
    void write_interrupt_block();

    inline register_t pop_stack() {
      register_t r = *((register_t*)((mem_loc_t)regs_struct->rsp + TRACE_STACK_OFFSET + move_stack_by));
      move_stack_by += sizeof(register_t);
      return r;
    }

    inline void push_stack(register_t v) {
      move_stack_by -= sizeof(register_t);
      *((register_t*)((mem_loc_t)regs_struct->rsp + TRACE_STACK_OFFSET + move_stack_by)) = v;
    }


    register_t get_opr_value(const ud_operand_t *opr);


    // static void tracer_start_cb(intptr_t ptr);

  private:

    struct resume_struct_s {
      register_t r12;
      register_t r13;
      register_t r14;
      register_t r15;
      register_t rbx;
      register_t rbp;
      register_t resume_addr; // not used?
      register_t stack_pointer;
    } resume_struct;

    struct user_regs_struct *regs_struct;
    int64_t move_stack_by = 0;

    std::shared_ptr<CodeBuffer> buffer;
    ud_t disassm;
    uint64_t udis_loc;

    boost::context::fcontext_t self_context;
    boost::context::fcontext_t running_context;

#ifndef NDEBUG
    unsigned long before_stack = 0xdeadbeef;
#endif
    char stack[1024 * 8];
#ifndef NDEBUG
    unsigned long after_stack = 0xdeadbeef;
#endif
  };

  struct jump_instruction_info {
    bool is_jump = false;
    bool is_local_jump = false;
    int64_t local_jump_location = 0;

  };

}



#endif // REDMAGIC_TRACER_H_
