#include "jit_internal.h"

#include <iostream>
using namespace std;

using namespace redmagic;

namespace redmagic {
  ChildManager *child_manager = nullptr;
}

static pid_t gettid() {
  return syscall(__NR_gettid);
}

extern "C" void redmagic_backwards_branch(void *id) {
  child_manager->backwards_branch(id);
}

extern "C" void redmagic_force_begin_trace() {
  child_manager->begin_trace();
}

extern "C" void redmagic_force_end_trace() {
  child_manager->end_trace();
}

void ChildManager::backwards_branch(void *id) {
  int cnt = ++branch_count[id];
  // TODO: change the threshold to something meaningful
  if(cnt > 10) {
    trace_branch = id;
    begin_trace();
  }
}

void ChildManager::begin_trace() {
  Communication_struct msg;
  msg.thread_pid = gettid();
  msg.op = START_TRACE;

  if(write(send_pipe, &msg, sizeof(msg)) != sizeof(msg)) {
    perror("failed to write msg to pipe");
  }

  cerr << "begin traceme\n" << flush;

  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  //asm("int3");
  sleep(1);
  raise(SIGSTOP);
  cerr << "child resumed\n" << flush;
}

void ChildManager::end_trace() {
  // maybe use a bad instrunction or something here
}
