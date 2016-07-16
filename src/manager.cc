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

extern "C" void *__real_malloc(size_t);

extern "C" void redmagic_start() {
  if(manager != nullptr) {
    perror("redmagic_start called twice");
    ::exit(1);
  }
  //void *p = __real_malloc(sizeof(Manager) + 1024*12);
  //p = (void*)((((mem_loc_t)p) + 8*1024) & ~(0xfff));

  redmagic::manager = new Manager();
  // int r = mprotect(p, 4*1024, PROT_NONE);
  // assert(!r);
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

  void *ret;
  Tracer *l;
  {
    assert(tracer == nullptr);
    auto buff = make_shared<CodeBuffer>(4 * 1024 * 1024);
    l = tracer = new Tracer(buff);

    // int r = mprotect(this, 4*1024, PROT_READ | PROT_WRITE);
    // assert(!r);

    branches[(uint64_t)id].tracer = l;


    // r = mprotect(this, 4*1024, PROT_NONE);
    // assert(!r);

    trace_id = id;
    ret = l->Start(ret_addr);
    is_traced = true;
  }

  return ret;
}

void* Manager::end_trace(void *id) {
  Tracer *l;
  void *ret;
  {
    assert(id == trace_id);
    //if(tracer) {
    //trace[id] = tracer;
    l = tracer;
    //tracer = nullptr;
    trace_id = nullptr;
    is_traced = false;
    ret = l->EndTraceLoop();
  }
  return ret;
  //}
}

void* Manager::jump_to_trace(void *id) {
  //void *addr = trace[id]->get_address();
  assert(0);
}

void* Manager::backwards_branch(void *id, void *ret_addr) {
  if(is_traced) {
    if(id == trace_id) {
      return end_trace(id);
    }
  } else {
    // int r = mprotect(this, 4*1024, PROT_READ | PROT_WRITE);
    // assert(!r);

    branch_info *info = &branches[(uint64_t)id];
    int cnt = info->count++;

    // r = mprotect(this, 4*1024, PROT_NONE);
    // assert(!r);


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

  bool ret = true;

  // int r = mprotect(this, 4*1024, PROT_READ | PROT_WRITE);
  // assert(!r);

  if(no_trace_methods.find((uint64_t)id) != no_trace_methods.end())
    ret = false;

  // r = mprotect(this, 4*1024, PROT_NONE);
  // assert(!r);


  // somehow eventually causes a crash
// #ifndef NDEBUG
//   Dl_info dlinfo;
//   if(dladdr(id, &dlinfo) && dlinfo.dli_fbase == self_dlinfo.dli_fbase) {
//     //no_trace_methods.insert(id);
//     assert(0);
//     return false;
//   }
// #endif

  return ret;
}
