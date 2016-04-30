
#include "redmagic.h"
#include "jit_internal.h"


#include <iostream>
using namespace std;


struct redmagic_handle_t *redmagic_global_default = nullptr;

#define CHECK_GLOBAL(handle)                    \
  if(handle == nullptr) {                       \
    handle = redmagic_global_default;           \
  }

extern "C" struct redmagic_handle_t *redmagic_init() {
  auto r = new redmagic_handle_t;
  if(redmagic_global_default == nullptr) {
    redmagic_global_default = r;
  }
  return r;


}

extern "C" void redmagic_destroy(struct redmagic_handle_t *handle) {
  CHECK_GLOBAL(handle);
  if(redmagic_global_default == handle) {
    redmagic_global_default = nullptr;
  }
  delete handle;
}

extern "C" redmagic_thread_trace_t* redmagic_start_trace(struct redmagic_handle_t *handle) {
  CHECK_GLOBAL(handle);
  auto r = new redmagic_thread_trace_t;

  redmagic_thread_trace_t *prev_head;
  do {
    prev_head = handle->head;
    r->tail = prev_head;
    //handle->head = r;
  } while(!__sync_bool_compare_and_swap(&handle->head, prev_head, r));

  // get the pid of the current thread vs the processes
  r->pid = syscall(__NR_gettid);

  r->manager = std::thread([r](){
      struct user_regs_struct regs;
      cout << "requesting start with ptrace\n" << flush;
      ptrace(PTRACE_ATTACH, r->pid, nullptr, nullptr);
      r->flags |= 0x1;
      waitpid(r->pid, NULL, 0);
      cout << "subthread stopped\n" << flush;
      long i = ptrace(PTRACE_GETREGS, r->pid, &regs, NULL);
      cout << "sp:"<< regs.rsp << " " << regs.rip <<endl;
    });

  cout << "suspending: " << r->pid << endl << flush ;

  //  kill(r->pid, SIGSTOP);

  while((r->flags & 0x1) == 0) ;
  cout << "resumed\n" << flush;

  asm("int3");

  // going to have to wait for the new thread to start tracing this thread
  return r;
}
