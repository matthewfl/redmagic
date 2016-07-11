#include "jit_internal.h"
#include "tracer.h"

#include <dlfcn.h>

using namespace redmagic;
using namespace std;

namespace redmagic {
  thread_local bool is_traced = false;
  thread_local bool is_temp_disabled = false;
  thread_local bool is_running_compiled = false;

  Manager *manager = nullptr;

  thread_local Tracer* tracer = nullptr;
  thread_local void* trace_id = nullptr;
};



extern "C" void* red_user_force_begin_trace(void *id, void *ret_addr) {
  return manager->begin_trace(id, ret_addr);
}

extern "C" void* red_user_force_end_trace(void *id, void *ret_addr) {
  return manager->end_trace(id);
}

extern "C" void* red_user_force_jump_to_trace(void *id, void *ret_addr) {
  return manager->jump_to_trace(id);
}

extern "C" void* red_user_backwards_branch(void *id, void *ret_addr) {
  return manager->backwards_branch(id, ret_addr);
}

extern "C" void* red_user_fellthrough_branch(void *id, void *ret_addr) {
  assert(0);
  return NULL;
}

extern "C" void* red_user_ensure_not_traced(void *_, void *ret_addr) {
  assert(0);
  return NULL;
}

extern "C" void* red_user_temp_disable(void *_, void *ret_addr) {
  assert(0);
  return NULL;
}

extern "C" void* red_user_temp_enable(void *_, void *ret_addr) {
  assert(0);
  return NULL;
}

extern "C" void redmagic_start() {
  if(manager != nullptr) {
    perror("redmagic_start called twice");
    ::exit(1);
  }
  redmagic::manager = new Manager();
}

static const char *avoid_inlining_methods[] = {
  // inlining the allocator doesn't really help since it will have a lot of branching
  // in trying to find where there is open memory
  "malloc",
  "free",
  "realloc",
  "calloc",
  "exit",
  "abort",

  // we don't want to inline ourselves
  // so record the entry functions
  "redmagic_force_begin_trace",
  "redmagic_force_end_trace",
  "redmagic_force_jump_to_trace",
  "redmagic_backwards_branch",
  "redmagic_fellthrough_branch",
  "redmagic_ensure_not_traced",
  "redmagic_temp_disable",
  "redmagic_temp_enable",
};

Manager::Manager() {
  // need to preload methods that we do no want to trace
  // use RTLD_NOW to try and force it to resolve the symbols address rather than delaying
  void *dlh = dlopen(NULL, RTLD_NOW);
  for(int i = 0; avoid_inlining_methods[i] != NULL; i++) {
    void *addr = dlsym(dlh, avoid_inlining_methods[i]);
    assert(addr);
    no_trace_methods.insert((uint64_t)addr);
  }
  dlclose(dlh);

}

void* Manager::begin_trace(void *id, void *ret_addr) {

  Tracer *l;
  {
    assert(tracer == nullptr);
    auto buff = make_shared<CodeBuffer>(4 * 1024 * 1024);
    l = tracer = new Tracer(buff);
    branches[(uint64_t)id].tracer = l;
    trace_id = id;
    is_traced = true;
  }

  return l->Start(ret_addr);

}

void* Manager::end_trace(void *id) {
  assert(id == trace_id);
  //if(tracer) {
    //trace[id] = tracer;
  tracer = nullptr;
  trace_id = nullptr;
  is_traced = false;
  return NULL;
  //}
}

void* Manager::jump_to_trace(void *id) {
  //void *addr = trace[id]->get_address();
  assert(0);
}

void* Manager::backwards_branch(void *id, void *ret_addr) {
  branch_info *info = &branches[(uint64_t)id];
  if(is_traced) {
    if(id == trace_id) {
      return end_trace(id);
    }
  } else {
    int cnt = info->count++;
    if(cnt > CONF_NUMBER_OF_JUMPS_BEFORE_TRACE) {
      return begin_trace(id, ret_addr);
    }
  }
  return NULL;
}

void* Manager::fellthrough_branch(void *id) {
  if(trace_id == id) {
    if(is_traced) {
      return end_trace(id);
    }
  }
  return NULL;
}

namespace {
  Dl_info self_dlinfo;
  static void _nonamef() {}
  struct _noname {
    _noname() {
      if(!dladdr((void*)&_nonamef, &self_dlinfo)) {
        perror("failed to get dlinfo for self");
      }
    }
  } _noinst;
}

bool Manager::should_trace_method(void *id) {
  if(no_trace_methods.find((uint64_t)id) != no_trace_methods.end())
    return false;

#ifndef NDEBUG
  Dl_info dlinfo;
  if(dladdr(id, &dlinfo) && dlinfo.dli_fbase == self_dlinfo.dli_fbase) {
    //no_trace_methods.insert(id);
    assert(0);
    return false;
  }
#endif

  return true;
}
