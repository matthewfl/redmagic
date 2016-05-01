#if 0

#include "redmagic.h"
#include "jit_internal.h"

#include "udis86.h"

#include <iostream>
using namespace std;


struct redmagic_handle_t *redmagic_global_default = nullptr;

// #define CHECK_GLOBAL(handle)                    \
//   if(handle == nullptr) {                       \
//     handle = redmagic_global_default;           \
//   }

static int udis_input_hook(ud_t *obj) {
  // this method is suppose to only go forward one byte each time
  // if the skip method is called then this just get call n times, so not too useful
  struct redmagic_handle_t *user = (struct redmagic_handle_t*)ud_get_user_opaque_data(obj);

  unsigned long at = user->read_offset;
  long res = ptrace(PTRACE_PEEKDATA, user->child_pid, at, NULL);
  // TODO: make this cache the internal result
  user->read_offset++;
  return res & 0xff;
}



extern "C" void redmagic_start() {
  // auto r = new redmagic_handle_t;
  // if(redmagic_global_default == nullptr) {
  //   redmagic_global_default = r;
  // }
  // return r;

  pid_t child = fork();
  if(child == 0) {
    // we are the child process
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    // allow for the parent processes to connect
    asm("int3");

    return;// NULL;
  } else {
    auto r = new redmagic_handle_t;
    redmagic_global_default = r;
    r->child_pid = child;

    ud_t disassm;
    ud_init(&disassm);
    ud_set_user_opaque_data(&disassm, r);
    ud_set_input_hook(&disassm, udis_input_hook);
    ud_set_mode(&disassm, 64); // 64 bit
    ud_set_vendor(&disassm, UD_VENDOR_INTEL);
    ud_set_syntax(&disassm, UD_SYN_INTEL);

    int res, stat;
    // wait for a traceme call to arrive
    res = waitpid(child, &stat, WUNTRACED);
    cout << "attached to childed: " << res << " " << stat << endl << flush;
    if((res != child) || !(WIFSTOPPED(stat))) {
      cerr << "unexpected state\n";
      exit(-1);
    }
    //struct user_regs_struct regs, oregs;
    // ptrace(PTRACE_GETREGS, r->child_pid, &regs, NULL);
    // cout << "got back regs\n" << flush;

    // while(waitpid(child, NULL, WNOHANG) == 0) {
    //   ptrace(PTRACE_CONT, child, NULL, NULL);
    //   wait(NULL);
    //   long i = ptrace(PTRACE_GETREGS, child, &regs, NULL);
    //   //if(memcmp(&regs,&oregs, sizeof(regs)) != 0) {
    //   cout << "a:" << regs.rip << endl << flush;
    //   oregs = regs;
    //     //}
    //   //asm("int3");
    //   ptrace(PTRACE_CONT, child, NULL, NULL);
    // }

    // http://www.secretmango.com/jimb/Whitepapers/ptrace/ptrace.html

    while(true) {
      if((res = ptrace(PTRACE_SINGLESTEP, child, NULL, NULL)) < 0) {
        cerr << "failed single step\n";
        exit(-1);
      }
      res = wait(&stat);

      int signo;
      if((signo = WSTOPSIG(stat)) == SIGTRAP) {
        signo = 0;
      }
      if(signo == SIGINT) {
        cerr << "processes was killed\n";
        exit(-1);
      }

      struct user_regs_struct regs;
      if(ptrace(PTRACE_GETREGS, child, &regs, &regs) < 0) {
        cerr << "failed to get regs\n";
        exit(-1);
      }

      r->pc = regs.rip;
      r->read_offset = regs.rip;
      ud_set_pc(&disassm, regs.rip);

      if (!ud_disassemble(&disassm)) {
        cerr << "fail disassm\n";
        exit(-1);
      }


      cout << "instrunction pointer: "<<regs.rip <<" " << ud_insn_asm(&disassm) << endl;



    }


    // this does not return in the parent processes
    exit(0);
  }
}

// extern "C" void redmagic_destroy(struct redmagic_handle_t *handle) {
//   CHECK_GLOBAL(handle);
//   if(redmagic_global_default == handle) {
//     redmagic_global_default = nullptr;
//   }
//   delete handle;
// }

// extern "C" redmagic_thread_trace_t* redmagic_start_trace(struct redmagic_handle_t *handle) {
//   CHECK_GLOBAL(handle);
//   auto r = new redmagic_thread_trace_t;

//   redmagic_thread_trace_t *prev_head;
//   do {
//     prev_head = handle->head;
//     r->tail = prev_head;
//     //handle->head = r;
//   } while(!__sync_bool_compare_and_swap(&handle->head, prev_head, r));

//   // get the pid of the current thread vs the processes
//   r->pid = syscall(__NR_gettid);

//   r->manager = std::thread([r](){
//       struct user_regs_struct regs;
//       cout << "requesting start with ptrace\n" << flush;
//       ptrace(PTRACE_ATTACH, r->pid, nullptr, nullptr);
//       r->flags |= 0x1;
//       waitpid(r->pid, NULL, 0);
//       cout << "subthread stopped\n" << flush;
//       long i = ptrace(PTRACE_GETREGS, r->pid, &regs, NULL);
//       cout << "sp:"<< regs.rsp << " " << regs.rip <<endl;
//     });

//   cout << "suspending: " << r->pid << endl << flush ;

//   //  kill(r->pid, SIGSTOP);

//   while((r->flags & 0x1) == 0) ;
//   cout << "resumed\n" << flush;

//   asm("int3");

//   // going to have to wait for the new thread to start tracing this thread
//   return r;
// }

#endif
