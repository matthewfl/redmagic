#ifndef REDMAGIC_TRACER_H_
#define REDMAGIC_TRACER_H_
#include "jit_internal.h"

#include "constants.h"


namespace redmagic {

  struct jump_instruction_info {
    bool is_jump = false;
    bool is_local_jump = false;
    int64_t local_jump_location = 0;
  };

  class Tracer {
  public:
    Tracer(std::shared_ptr<CodeBuffer> buffer);

    void* Start(void *start_addr);

    inline mem_loc_t _get_udis_location() { return udis_loc++; }

    void Run(void *);
  private:


    void set_pc(uint64_t);

    struct jump_instruction_info decode_instruction();
    void evaluate_instruction();
    void replace_rip_instruction();

    void continue_program(mem_loc_t);
    void write_interrupt_block();

    // jump back to the normal execution of this program
    void abort();

    inline register_t pop_stack() {
      register_t r = *((register_t*)((mem_loc_t)regs_struct->rsp + TRACE_STACK_OFFSET + move_stack_by));
      move_stack_by += sizeof(register_t);
      return r;
    }

    inline void push_stack(register_t v) {
      move_stack_by -= sizeof(register_t);
      *((register_t*)((mem_loc_t)regs_struct->rsp + TRACE_STACK_OFFSET + move_stack_by)) = v;
    }

    struct opr_value {
      ud_type type;
      bool is_ptr;
      union {
        mem_loc_t address;
        register_t *address_ptr;
        register_t value;
      };
    };

    opr_value get_opr_value(const ud_operand_t *opr);


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


    // Run variables
    mem_loc_t current_location;
    mem_loc_t last_location;
    mem_loc_t generated_location;
    struct jump_instruction_info jmp_info;
    bool rip_used = false;
    uint64_t icount = 0;

    mem_loc_t interrupt_block_location;


#ifndef NDEBUG
    unsigned long before_stack = 0xdeadbeef;
#endif
    char stack[1024 * 8];
#ifndef NDEBUG
    unsigned long after_stack = 0xdeadbeef;
#endif
  };


}



#endif // REDMAGIC_TRACER_H_
