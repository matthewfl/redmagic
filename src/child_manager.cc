#include "jit_internal.h"

#include <iostream>
using namespace std;

#include <assert.h>

using namespace redmagic;

namespace redmagic {
  ChildManager *child_manager = nullptr;
  thread_local bool is_traced = false;
  thread_local bool is_temp_disabled = false;
  thread_local bool is_running_compiled = false;
  thread_local mem_loc_t return_disable_loc = 0;
}


extern "C" void redmagic_backwards_branch(void *id) {
  child_manager->backwards_branch(id);
}

extern "C" void redmagic_force_begin_trace(void *id) {
  child_manager->begin_trace();
}

extern "C" void redmagic_force_end_trace(void *id) {
  child_manager->end_trace();
}

extern "C" void redmagic_force_jump_to_trace(void *id) {

}

extern "C" {
  void red_asm_temp_disable_trace();
  void red_asm_temp_enable_trace();
  void red_asm_end_trace();
  void red_asm_begin_trace();
  void red_asm_return_after_method_call();
}

namespace redmagic {
  const Int3_location action_table[] = {
    { red_asm_temp_disable_trace, TEMP_DISABLE_ACT },
    { red_asm_temp_enable_trace, TEMP_ENABLE_ACT },
    { red_asm_end_trace, END_TRACE_ACT },
    { red_asm_begin_trace, BEGIN_TRACE_ACT },
    { red_asm_return_after_method_call, RETURN_FROM_METHOD_ACT },
    { NULL, MAX_ACT }
  };
}


extern "C" void __attribute__ ((optimize("O0"))) redmagic_temp_disable() {
  if(is_traced) {
    // the rax register will contain an address that we can jump to when this thing is compiled
    __asm__("" ::: "%rax");
    red_asm_temp_disable_trace();
    __asm__("mov %%rax, %[a] \n"
            : [a]"=r" (return_disable_loc)
            :
            :
            );
  }
  if(is_temp_disabled) {
    perror("can't temporarly disable the jit twice in a row");
  }
  is_temp_disabled = true;
}

extern "C" void __attribute__ ((optimize("O0"))) redmagic_temp_enable() {
  if(is_running_compiled) {
    // then we should have a location to jump back to
    mem_loc_t m = return_disable_loc;
    return_disable_loc = 0;
    __asm__("jmp *%[a] \n"
            :
            : [a]"r" (m)
            :
            );
  }
  if(!is_temp_disabled) {
    perror("can't renable trace when it isn't disabled");
  }
  is_temp_disabled = false;
  if(is_traced) {
    red_asm_temp_enable_trace();
  }
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

  is_traced = true;

  // it appears that unable to start trace on self after some other operations
  // have occured first when forked

  raise(SIGSTOP);
  // wait for the tracer to get started
  //asm("int3");
  red_asm_begin_trace();
}


void ChildManager::end_trace() {
  // maybe use a bad instrunction or something here
  if(!is_traced) {
    perror("ending trace when was not started\n");
  }
  red_asm_end_trace();
  is_traced = false;

  cerr << "requesting trace\n" << flush;

  Communication_struct msg;
  msg.thread_pid = gettid();
  msg.op = END_TRACE;
  if(write(send_pipe, &msg, sizeof(msg)) != sizeof(msg)) {
    perror("failed to write end msg");
  }

  Communication_struct res;
  if(read(recv_pipe, &res, sizeof(res)) < sizeof(res)) {
    perror("failed to read comm struct");
  }
  assert(res.op == SEND_TRACE);
  assert(res.thread_pid == msg.thread_pid);
  vector<JumpTrace> vec;
  vec.resize(res.number_jump_steps);

  size_t len = sizeof(JumpTrace) * res.number_jump_steps;
  if(read(recv_pipe, vec.data(), len) != len) {
    perror("failed to read the trace steps");
  }



}
