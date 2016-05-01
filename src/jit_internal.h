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
//#include <sys/reg.h>

#include <sys/syscall.h>

#include <string.h>

#include <thread>
#include <atomic>

#include <cstddef>

#define container_of(ptr, type, member) ({                      \
      const typeof( ((type *)0)->member ) *__mptr = (ptr);      \
      (type *)( (char *)__mptr - offsetof(type,member) );})

typedef unsigned long long int register_type;

struct redmagic_handle_t {
  struct redmagic_thread_trace_t *head = nullptr;
  pid_t child_pid;

  // hacky stuff to get things working....
  register_type pc;
  unsigned long read_offset;
};

struct redmagic_thread_trace_t {
  struct redmagic_thread_trace_t *tail = nullptr;
  std::thread manager;
  pid_t pid;
  std::atomic<int> flags;
};


#endif
