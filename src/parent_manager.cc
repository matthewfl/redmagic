#include "jit_internal.h"

#include <assert.h>

#include <iostream>
using namespace std;

using namespace redmagic;

namespace redmagic {
  ParentManager *parent_manager = nullptr;
}

extern "C" void redmagic_start() {
  assert(parent_manager == nullptr);
  assert(child_manager == nullptr);
  int send_child_pipe[2];
  int send_parent_pipe[2];
  if(pipe(send_child_pipe) < 0 || pipe(send_parent_pipe) < 0) {
    cerr << "failed to create pipe\n";
    exit(-1);
  }
  pid_t child_pid = fork();

  if(child_pid == -1) {
    cerr << "fork failed\n";
    exit(-1);
  } else if(child_pid == 0) {
    // we are the child
    child_manager = new ChildManager(send_parent_pipe[1], send_child_pipe[0]);
    return;
  } else {
    // we are the parent
    parent_manager = new ParentManager(send_child_pipe[1], send_parent_pipe[0], child_pid);
    parent_manager->run();
    cerr << "the parent manager has returned, this should never happen\n";
    exit(-1);
  }
}

void ParentManager::run() {
  while(1) {
    Communication_struct msg;
    read(recv_pipe, &msg, sizeof(msg));
    switch(msg.op) {
    case START_TRACE: {
      cerr << "got req for trace\n" << flush;
      auto t = new Tracer(this, msg.thread_pid);
      tracers[msg.thread_pid] = t;
      t->start();
      break;
    }
    case END_TRACE: {
      cerr << "got req to end trace\n" << flush;
      auto t = tracers[msg.thread_pid];
      Communication_struct rm;
      rm.op = SEND_TRACE;
      rm.thread_pid = msg.thread_pid;
      rm.number_jump_steps = t->getSteps();
      if(write(send_pipe, &msg, sizeof(msg)) != sizeof(msg)) {
        perror("failed to send msg");
      }
      t->writeTrace(send_pipe);

      break;
    }
    }
  }
}

void ParentManager::set_program_pval(mem_loc_t where, uint8_t what) {
  auto f = program_map.find(where);
  if(f != program_map.end()) {
    if(f->second != what) {
      perror("trying to set two different values for the program map");
    }
    return;
  }
  program_map.insert(make_pair(where, what));
}

int ParentManager::get_program_pval(mem_loc_t where) {
  auto f = program_map.find(where);
  if(f == program_map.end()) {
    // we were not able to find it
    return -1;
  }
  return f->second;
}

bool ParentManager::is_ignored_method(mem_loc_t where) {
  return ignored_methods.find(where) != ignored_methods.end();
}
