#include "jit_internal.h"

#ifdef CONF_COMPILE_IN_PARENT
# include "compiler.h"
#endif

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
  std::thread tracer_thread([this](){
      tracing_pid = gettid();

      struct sigaction sa;
      sa.sa_handler = [](int signum) {};
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;

      if(sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("failed to configure signal handler");
      }

      waitpid(-1, NULL);
    });

  while(1) {
    Communication_struct msg;
    cerr << "waiting on read\n" << flush;
    read(recv_pipe, &msg, sizeof(msg));
    switch(msg.op) {
    case START_TRACE: {
      cerr << "got req for trace\n" << flush;
      start_child(msg.thread_pid);
      // auto t = new Tracer(this, msg.thread_pid);
      // tracers[msg.thread_pid] = t;
      // t->start();
      break;
    }
    case END_TRACE: {
      cerr << "got req to end trace\n" << flush;
      auto t = tracers[msg.thread_pid];
#ifdef CONF_COMPILE_IN_PARENT
      auto c = new Compiler(t);
#else
      Communication_struct rm;
      rm.op = SEND_TRACE;
      rm.thread_pid = msg.thread_pid;
      rm.number_jump_steps = t->getSteps();
      if(write(send_pipe, &rm, sizeof(rm)) != sizeof(rm)) {
        perror("failed to send msg");
      }
      t->writeTrace(send_pipe);
#endif
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

struct context_passed {
  pid_t pid;
  int stat;
  void *thread;
};

// might be faster to manually just do the swapping
// since we know that we don't care about the floating point registers and we can avoid changing flag register in the kernel with syscalls

pid_t ParentManager::waitpid(pid_t pid, int *stat) {

  using namespace boost::context;
  context_passed cp;

  fcontext_t *switch_to, *switch_from;
  int sig;
  waiting_thread *looking;

  if(current_thread == NULL) {
    switch_from = &main_wait_context;
  } else {
    switch_from = &current_thread->context;
  }

  assert(current_thread == NULL || current_thread->tracer->getpid() == pid || (pid == -1 && stat == NULL));

 do_wait:

  cp.pid = wait(&cp.stat);
  if(pid == -1 && stat == NULL) {
    // this current thread is done, needs to be deleted
    if(current_thread != NULL)
      current_thread->pid = -1;
    delete_thread = current_thread;
  }
  if(errno == EINTR && cp.pid == -1) {
    // wait was interupted by some signal
    // then we are starting a new tracer thread
    errno = 0;
    current_thread = head_thread;
    switch_to = &current_thread->context;
    cp.pid = current_thread->pid;
    cp.thread = current_thread;
    goto do_switch;
  }
  sig = WIFSIGNALED(cp.stat);
  if(WIFEXITED(cp.stat)) {
    ::exit(WEXITSTATUS(cp.stat));
  }
  if(cp.pid == current_thread->pid) {
    goto do_return;
  }
  looking = head_thread;
  while(looking != NULL && looking->pid != cp.pid) {
    looking = looking->next;
  }

  if(looking == NULL) {
    // then we didn't find anyone to wait
    goto do_wait;
  }

  switch_to = &looking->context;

  goto do_switch;

 do_switch:
  assert(&current_thread->context == switch_to);
  assert(switch_from != switch_to);
  cp = *(context_passed*)jump_fcontext(switch_from, *switch_to, (intptr_t)&cp);

  if(delete_thread != NULL) {
    // perform the delete operation
    if(delete_thread->next != NULL) {
      if(delete_thread == head_thread) {
        head_thread = delete_thread->next;
      } else {
        waiting_thread *parent = head_thread;
        while(parent->next != delete_thread && parent->next != NULL) {
          parent = parent->next;
        }
        parent->next = delete_thread->next;
      }
    }
    delete delete_thread;
    delete_thread = NULL;
  }

 do_return:
  assert(pid == cp.pid);
  assert(stat);
  *stat = cp.stat;
  return cp.pid;
}

// void ParentManager::start_waitthread() {
//   waitpid(-1, NULL);
// }

void ParentManager::start_child_cb(intptr_t ptr) {
  using namespace boost::context;
  context_passed cp = *(context_passed*)ptr;
  waiting_thread *t = static_cast<struct waiting_thread*>(cp.thread);
  t->tracer->run(); // this should not return
  assert(0);
  // t->pid = -1; // indicate that it is done waiting???
  // int a;
  // waitpid(-1, &a);
  //jump_fcontext(&cp.thread->context, main_wait_context, &cp);
}


void ParentManager::start_child(pid_t pid) {
  using namespace boost::context;
  Tracer *t = new Tracer(this, pid);
  tracers[pid] = t;
  struct waiting_thread *child = new waiting_thread;
  // this method call right here is SO MUCH BULL SHIT, having to manually offset the stack +sizeof, this was not properly included in the docs....
  // I guess that this is the "lower level interface" but this seems to be what is documented well
  // using these function should be fairly fast since these are just a dozen assembly instructions each
  child->context = make_fcontext(child->stack + sizeof(child->stack), sizeof(child->stack), start_child_cb);
  child->pid = pid;
  child->tracer = t;
  child->next = head_thread;
  head_thread = child;
  // send msg that it should start this thread
  // TODO: some locking to ensure that this thread is started before another one can start
  if(kill(tracing_pid, SIGUSR1) < 0) {
    perror("failed to kill the waiting thread\n");
  }
}
