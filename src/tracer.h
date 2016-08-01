#ifndef REDMAGIC_TRACER_H_
#define REDMAGIC_TRACER_H_
#include "jit_internal.h"

#include "constants.h"

namespace redmagic {

  struct jump_instruction_info {
    bool is_jump = false;
    bool is_local_jump = false;
    int64_t local_jump_offset = 0;
  };

  class Tracer {
  public:
    Tracer(CodeBuffer* buffer);
    ~Tracer();

    // create a new tracer with jumps to new address
    void* Start(void *start_addr);


    inline mem_loc_t _get_udis_location() { return udis_loc++; }

    void Run(struct user_regs_struct*);

    // we are done with the loop, so resume normal execution
    void* EndTraceFallthrough(bool check_id=true);
    // if this was a nested trace then we want to branch back to the main trace
    //void *EndTraceFallthroughNestedLoop(void *target_addr);
    // we are jumping back to the top of the loop, so do that
    void* EndTraceLoop();

    // if there was a fallthrough statement called but with not our own branch
    // check that it can't possibly be our own loop
    void* CheckNotSelfFellthrough();

    // ending a branchable block (eval frame) so all tracers that are left alive atm
    // need to have their proper fallthrough methods called
    void* EndTraceEndBranchable();

    // if there is another backwards branch inside of this backwards branch
    // the there is a nested loop that we should trace
    void JumpToNestedLoop(void *nested_trace_id);

    void JumpFromNestedLoop(void *resume_pc); // { set_pc((uint64_t)resume_pc); }

    // generate a temp disable command, sets the thread local where to resume to address
    void* TempDisableTrace();
    void TempEnableTrace(void *resume_pc);// { set_pc((uint64_t)resume_pc); }

    // push the merge block stack with the current address
    void* BeginMergeBlock();
    // end the current merge block
    void* EndMergeBlock();

    void* DeleteLastCall();

    void set_merge_target(mem_loc_t target) {
      assert(merge_resume == 0);
      merge_resume = target;
    }

    void* ReplaceIsTracedCall();

    inline void *get_start_location() { return (void*)trace_start_location; }

    inline void set_where_to_patch(int32_t *addr) {
      assert(finish_patch_addr == nullptr);
      finish_patch_addr = addr;
    }

    inline mem_loc_t get_pc() { return udis_loc; }

    inline uint64_t* get_loop_counter() { return trace_loop_counter; }

  public:
    // std::mutex _generation_mutex;
    // std::unique_lock<std::mutex> generation_lock = std::unique_lock<std::mutex>(_generation_mutex);

  private:

    void set_pc(uint64_t);

    struct jump_instruction_info decode_instruction();
    void evaluate_instruction();
    void replace_rip_instruction();

    // continue program might not return, so any cleanup needs to be peformed before it is called
    void continue_program(mem_loc_t);
    void write_interrupt_block();

    // jump back to the normal execution of this program, no clean up
    void abort();

    // delete the current trace and abort
    void kill_trace();

    // what ever the current function is, there is something about it that we don't like
    // so blacklist it and kill the current trace
    void blacklist_function();

    // write int3 and switch the stack to that
    void run_debugger();

    // when done patch the address that needs to link to this trace
    void finish_patch();

    inline register_t pop_stack() {
      register_t r = *((register_t*)((mem_loc_t)regs_struct->rsp + move_stack_by));
      move_stack_by += sizeof(register_t);
      return r;
    }

    inline register_t peek_stack() {
      register_t r = *((register_t*)((mem_loc_t)regs_struct->rsp + move_stack_by));
      return r;
    }

    inline void push_stack(register_t v) {
      move_stack_by -= sizeof(register_t);
      *((register_t*)((mem_loc_t)regs_struct->rsp + move_stack_by)) = v;
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

#ifndef NDEBUG
    bool debug_check_abort();
#endif

    // static void tracer_start_cb(intptr_t ptr);

  public:
    std::atomic<mem_loc_t> tracing_from;
    uint32_t owning_thread;
    int32_t owning_frame_id;


    bool did_abort = false;

    // used for printing
    inline mem_loc_t generated_pc() { return generated_location; }
    inline int64_t get_icount() { return icount; }

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
    } resume_struct = {0};

    struct user_regs_struct *regs_struct = nullptr;
    int64_t move_stack_by = 0;

    CodeBuffer* buffer;
    ud_t disassm;
    uint64_t udis_loc;


    // Run variables
    mem_loc_t current_location;
    mem_loc_t last_location;
    mem_loc_t generated_location;
    struct jump_instruction_info jmp_info;
    bool rip_used = false;
    int64_t icount = 0;

#ifdef CONF_ATTEMPT_FORWARD_JUMP_INLINE
    mem_loc_t last_local_jump = 0;
    mem_loc_t local_jump_min_addr = 0;
#endif

    mem_loc_t interrupt_block_location;

    // in the case that we don't actually want to inline this method, then we need to be able to backout
    int64_t last_call_instruction = -1;
    size_t last_call_generated_op; // where we have the corresponding gened ops (eg push ret addr)
    mem_loc_t last_call_ret_addr;
    mem_loc_t last_call_pc;
    mem_loc_t current_not_traced_call_addr = 0; // address of the call that is currently being execuited if we aren't tracing
    mem_loc_t *current_not_traced_call_ret_loc = nullptr;

    mem_loc_t trace_start_location; // where this current trace begins
    //mem_loc_t loop_start_location; // where it should branch the loop back to

    int32_t *finish_patch_addr = nullptr;

    std::vector<mem_loc_t> method_address_stack;
    std::vector<mem_loc_t> merge_block_stack;

    mem_loc_t merge_resume = 0;

    uint64_t *trace_loop_counter = nullptr;

    // mem_loc_t stack;

#ifndef NDEBUG
    unsigned long before_stack = 0xdeadbeef;
#endif
    char stack_[TRACE_STACK_SIZE + 64];
#ifndef NDEBUG
    unsigned long after_stack = 0xdeadbeef;
#endif
  };


}



#endif // REDMAGIC_TRACER_H_
