#include "jit_internal.h"

#ifndef __x86_64__
  #error "expecting 64 bit compile"
#endif

#include <iostream>
using namespace std;

using namespace redmagic;

namespace redmagic {
  int udis_input_hook(ud_t *ud) {
    Tracer* trace = (Tracer*)ud_get_user_opaque_data(ud);

    long res = ptrace(PTRACE_PEEKDATA, trace->thread_pid, trace->read_offset, NULL);
    trace->read_offset++;

    // TODO: cache the result of this since we get 4 bytes at a time
    // TODO: check that we are reading the correct byte and not off by 3
    return res & 0xff;

  }
}


Tracer::Tracer(ParentManager *man, pid_t pid):
  manager(man), thread_pid(pid) {
  ud_init(&disassm);
  ud_set_user_opaque_data(&disassm, this);
  ud_set_input_hook(&disassm, udis_input_hook);
  ud_set_mode(&disassm, 64); // 64 bit
  ud_set_vendor(&disassm, UD_VENDOR_INTEL);
  ud_set_syntax(&disassm, UD_SYN_INTEL);


}

void Tracer::start() {
  running_thread = std::thread([this](){
      this->run();
    });
}


void Tracer::run() {
  cerr << "tracer running " << thread_pid << endl << flush;
  int res, stat;
  res = waitpid(thread_pid, &stat, WUNTRACED);
  if((res != thread_pid) || !(WIFSTOPPED(stat))) {
    cerr << "unexpected state when beginning trace\n";
    ::exit(-1);
  }
  while(!exit) {
    if(ptrace(PTRACE_SINGLESTEP, thread_pid, NULL, NULL) < 0) {
      cerr << "failed single step" << flush;
    }
    res = waitpid(thread_pid, &stat, 0);
    // TODO: handle various states of this child process
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, thread_pid, &regs, &regs) < 0) {
      perror("failed to get regs");
    }

    read_offset = regs.rip;
    ud_set_pc(&disassm, regs.rip);
    if(!(res = ud_disassemble(&disassm))) {
      perror("failed to dissassm");
    }
    cout << "\t" << ud_insn_asm(&disassm) << endl << flush;
  }
}
