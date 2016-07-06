#ifndef REDMAGIC_INTERNAL_H_
#define REDMAGIC_INTERNAL_H_

#include "redmagic.h"

#include "config.h"

#ifndef __cplusplus
#error "require c++ to compile red magic"
#endif

#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

#include <sys/syscall.h>

#include <string.h>

#include <thread>
#include <atomic>
#include <map>
#include <vector>
#include <set>

#include <errno.h>

#include <boost/context/all.hpp>

// #include <cstddef>

// #define container_of(ptr, type, member) ({                      \
//       const typeof( ((type *)0)->member ) *__mptr = (ptr);      \
//       (type *)( (char *)__mptr - offsetof(type,member) );})

// typedef unsigned long long int register_type;

// struct redmagic_handle_t {
//   struct redmagic_thread_trace_t *head = nullptr;
//   pid_t child_pid;

//   // hacky stuff to get things working....
//   register_type pc;
//   unsigned long read_offset;


// };


#include "udis86.h"


namespace redmagic {

  class ChildManager;
  class ParentManager;
  class Tracer;

  struct JumpTrace;
  struct Communication_struct;
  struct Check_struct;

  class Compiler;
  class CodeBuffer;

  typedef decltype(((struct user_regs_struct*)(NULL))->r15) register_t;
  typedef uint64_t mem_loc_t; // a memory location in the debugged program

  // helper functions for during the trace
  extern "C" void red_unexpected_branch();

  class ChildManager {
  public:
    void backwards_branch(void*);
    void fellthrough_branch(void*);
    void begin_trace();
    void end_trace();
    void ensure_not_traced();

    ChildManager(int send, int recv) : send_pipe(send), recv_pipe(recv) {}

  private:
    // TODO: use an atomic map here
    std::map<void*, int> branch_count;
    bool in_trace = false;
    void *trace_branch;
    int send_pipe, recv_pipe;
  };

  class ParentManager {
  public:
    void run();

    ParentManager(int send, int recv, pid_t child): send_pipe(send), recv_pipe(recv), child_pid(child) {}

    void set_program_pval(mem_loc_t where, uint8_t what);
    int get_program_pval(mem_loc_t where);
    bool is_ignored_method(mem_loc_t where);

    pid_t waitpid(pid_t pid, int *stat);

  private:
    void start_child(pid_t pid);
    //    static void start_waitthread();
    static void start_child_cb(intptr_t);

  private:
    int send_pipe, recv_pipe;
    pid_t child_pid;
    std::map<pid_t, Tracer*> tracers;
    std::map<mem_loc_t, uint8_t> program_map;
    std::set<mem_loc_t> ignored_methods;



    struct waiting_thread {
      unsigned long before_stack = 0xdeadbeef;
      char stack[8192];
      unsigned long after_stack = 0xdeadbeef;
      pid_t pid;
      boost::context::fcontext_t context;
      struct waiting_thread *next;
      Tracer *tracer;
    };

    boost::context::fcontext_t main_wait_context;
    //boost::context::fcontext_t main_thread;

    struct waiting_thread *current_thread = NULL;
    struct waiting_thread *head_thread = NULL;
    struct waiting_thread *delete_thread = NULL;

    pid_t tracing_pid;

  };

  class Tracer {
    unsigned long before_tracer = 0xdeadbeef;
  public:
    Tracer(ParentManager *man, pid_t pid); //: manager(man), thread_pid(pid) {}
    //void start();
    pid_t getpid() { return thread_pid; }
    int getSteps();
    void writeTrace(int fn);


    void run();

  private:
    Check_struct decode_instruction();

    unsigned char readByte(mem_loc_t where);
    void writeByte(mem_loc_t where, uint8_t b);
    void setOffset(mem_loc_t where);


  private:
    ParentManager *manager;
    const pid_t thread_pid;
    std::thread running_thread;
    //bool exit = false;
    bool temp_disable = false;
    ud_t disassm;
    friend int udis_input_hook(ud_t*);
    mem_loc_t read_offset;

    long read_cache;
    mem_loc_t read_cache_loc = -1;

    unsigned int num_ins = 0;

    std::vector<JumpTrace> traces;

    unsigned long after_tracer = 0xdeadbeef;

#ifdef CONF_COMPILE_IN_PARENT
    friend class Compiler;
    friend class CodeBuffer;
#endif

  };

  extern ChildManager *child_manager;
  extern ParentManager *parent_manager;

  struct Check_struct {
    // which register to check
    // -1 if there is no need for a check
    // -2 if this is not a branch instruction
    int check_register;
    bool check_memory;
    // second register that represents that we are scaling memory_offset by some value, otherwise if -1, then scale memory_offset by -1
    int scale_register;
    mem_loc_t memory_offset;
    // check_register + scale_register * memory_offset

    union {
      register_t register_value;
      register_t memory_value;
    };
  };

  enum TraceOp {
    // represents that this is a typical instruction
    INST_TRACE_OP, // a standard jump instruction
    INST_LOOP_TRACE_OP, // a jump that is backwards and will execute multiple times in a row, eg only wait to exit is for this branch to fall through
    BEGIN_TRACE_OP, // pushed at the start of the tracing processes
    END_TRACE_OP,
    TEMP_BREAK_TRACE_OP, // temp_disable/enable method
    IGNORED_CALL_TRACE_OP, // when there is a call like malloc or some other registered call, work around it instead of tracing through it
  };

  struct JumpTrace {
    TraceOp op;
    register_t ins_pc;    // pc of where the instruction is located
    register_t target_pc; // pc after the instruction executed
    ud_mnemonic_code instruction;
    unsigned int ins_len;
    struct Check_struct check;
    // int check_register;
    // register_t register_value;
    // int instruction_len;
  };

  enum CommOp {
    // client ops
    START_TRACE,
    END_TRACE,

    // parent ops
    SEND_TRACE,

    SEND_COMPILE,

  };

  struct Communication_struct {
    CommOp op;
    pid_t thread_pid;
    union {
      int number_jump_steps;
      //struct JumpTrace jump;
    };
  };

  enum Int3_action {
    END_TRACE_ACT,
    BEGIN_TRACE_ACT,
    TEMP_DISABLE_ACT,
    TEMP_ENABLE_ACT,
    RETURN_FROM_METHOD_ACT,

    NO_ACT,

    MAX_ACT,
  };

  struct Int3_location {
    void (*location)();
    Int3_action act;
  };

  extern const Int3_location action_table[];


static pid_t gettid() {
  return syscall(__NR_gettid);
}

// convert a register from udis to sys/reg.h
static int ud_register_to_sys(ud_type t) {
  switch(t) {
  case UD_R_R15B:
  case UD_R_R15W:
  case UD_R_R15D:
  case UD_R_R15:
    return R15;
  case UD_R_R14B:
  case UD_R_R14W:
  case UD_R_R14D:
  case UD_R_R14:
    return R14;
  case UD_R_R13B:
  case UD_R_R13W:
  case UD_R_R13D:
  case UD_R_R13:
    return R13;
  case UD_R_R12B:
  case UD_R_R12W:
  case UD_R_R12D:
  case UD_R_R12:
    return R12;
  case UD_R_CH: // ??
  case UD_R_BP:
  case UD_R_EBP:
  case UD_R_RBP:
    return RBP;
  case UD_R_BL:
  case UD_R_BX:
  case UD_R_EBX:
  case UD_R_RBX:
    return RBX;
  case UD_R_R11B:
  case UD_R_R11W:
  case UD_R_R11D:
  case UD_R_R11:
    return R11;
  case UD_R_R10B:
  case UD_R_R10W:
  case UD_R_R10D:
  case UD_R_R10:
    return R10;
  case UD_R_R9B:
  case UD_R_R9W:
  case UD_R_R9D:
  case UD_R_R9:
    return R9;
  case UD_R_R8B:
  case UD_R_R8W:
  case UD_R_R8D:
  case UD_R_R8:
    return R8;
  case UD_R_AL:
  case UD_R_AX:
  case UD_R_EAX:
  case UD_R_RAX:
    return RAX;
  case UD_R_CL:
  case UD_R_CX:
  case UD_R_ECX:
  case UD_R_RCX:
    return RCX;
  case UD_R_DL:
  case UD_R_DX:
  case UD_R_EDX:
  case UD_R_RDX:
    return RDX;
  case UD_R_DH:
  case UD_R_SI:
  case UD_R_ESI:
  case UD_R_RSI:
    return RSI;
  case UD_R_BH:
  case UD_R_DI:
  case UD_R_EDI:
  case UD_R_RDI:
    return RDI;
    // orig rax
  case UD_R_RIP:
    // instrunction pointer??
    return RIP;
  case UD_R_CS:
    return CS;
    // eflags not directly accessable, use pushf and popf
  case UD_R_AH:
  case UD_R_SP:
  case UD_R_ESP:
  case UD_R_RSP:
    return RSP;
    // fsbase, gsbase
  case UD_R_DS:
    return DS;
  case UD_R_ES:
    return ES;
  case UD_R_FS:
    return FS;
  case UD_R_GS:
    return GS;
  default:
    return -1;
  }
}


}
// struct redmagic_thread_trace_t {
//   struct redmagic_thread_trace_t *tail = nullptr;
//   std::thread manager;
//   pid_t pid;
//   std::atomic<int> flags;
// };

// global instance of red magic
//extern struct redmagic_handle_t *redmagic_global_default;



#endif
