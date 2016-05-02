#ifndef REDMAGIC_INTERNAL_H_
#define REDMAGIC_INTERNAL_H_

#include "redmagic.h"

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

#include <errno.h>

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

  typedef decltype(((struct user_regs_struct*)(NULL))->r15) register_t;

  class ChildManager {
  public:
    void backwards_branch(void*);
    void begin_trace();
    void end_trace();

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

    void set_program_pval(void* where, unsigned char what);
    int get_program_pval(void* where);
  private:
    int send_pipe, recv_pipe;
    pid_t child_pid;
    std::map<pid_t, Tracer*> tracers;
    std::map<void*, unsigned char> program_map;
  };

  class Tracer {
  public:
    Tracer(ParentManager *man, pid_t pid); //: manager(man), thread_pid(pid) {}
    void start();
    pid_t getpid() { return thread_pid; }

  private:
    void run();
    Check_struct decode_instruction();

    unsigned char readByte(void *where);
    void writeByte(void *where, unsigned char b);

  private:
    ParentManager *manager;
    const pid_t thread_pid;
    std::thread running_thread;
    bool exit = false;
    ud_t disassm;
    friend int udis_input_hook(ud_t*);
    unsigned long read_offset;

    unsigned int read_cache;
    unsigned long read_cache_loc = -1;

    unsigned int num_ins = 0;
  };

  extern ChildManager *child_manager;
  extern ParentManager *parent_manager;

  enum CommOp {
    START_TRACE,
    END_TRACE,
  };

  struct Check_struct {
    // which register to check
    // -1 if there is no need for a check
    // -2 if this is not a branch instruction
    int check_register;
    bool check_memory;

    union {
      register_t register_value;
      register_t memory_value;
    };
  };

  struct JumpTrace {
    register_t ins_pc;    // pc of where the instruction is located
    register_t target_pc; // pc after the instruction executed
    ud_mnemonic_code instruction;
    struct Check_struct check;
    // int check_register;
    // register_t register_value;
    // int instruction_len;
  };

  struct Communication_struct {
    CommOp op;
    pid_t thread_pid;
    union {
      struct JumpTrace jump;
    };
  };

  enum Int3_action {
    END_TRACE_ACT,
    BEGIN_TRACE_ACT,
    TEMP_DISABLE_ACT,
    TEMP_ENABLE_ACT,

    NO_ACT,

    MAX_ACT,
  };

  struct Int3_location {
    void (*location)();
    Int3_action act;
  };

  extern const Int3_location action_table[];


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
