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

#include <thread>
#include <atomic>

struct redmagic_handle_t {
  struct redmagic_thread_trace_t *head = nullptr;
};

struct redmagic_thread_trace_t {
  struct redmagic_thread_trace_t *tail = nullptr;
  std::thread manager;
  pid_t pid;
  std::atomic<int> flags;
};


#endif
