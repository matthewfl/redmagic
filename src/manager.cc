#include "jit_internal.h"
#include "tracer.h"

#include <dlfcn.h>

using namespace redmagic;
using namespace std;

namespace redmagic {
  thread_local bool is_traced = false;
  thread_local bool is_temp_disabled = false;
  thread_local void *temp_disable_resume = nullptr;
  //thread_local bool is_running_compiled = false;

  Manager *manager = nullptr;

  thread_local Tracer* tracer = nullptr;
  thread_local void* trace_id = nullptr;

  thread_local vector<return_addr_info> trace_return_addr;

  thread_local uint32_t this_thread_id = 0;
}



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
  return manager->fellthrough_branch(id);
}

extern "C" void* red_user_ensure_not_traced(void *_, void *ret_addr) {
  assert(0);
  return NULL;
}

extern "C" void* red_user_temp_disable(void *_, void *ret_addr) {
  return manager->temp_disable();
  //return NULL;
}

extern "C" void* red_user_temp_enable(void *_, void *ret_addr) {
  return manager->temp_enable(ret_addr);
  //assert(0);
  //return NULL;
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

// namespace redmagic {
//   Tracer* get_tracer() {
//     if(tracer == nullptr) {
//       auto buff = make_shared<CodeBuffer>(4 * 1024 * 1024);
//       tracer = new Tracer(buff);
//     }
//     return tracer;
//   }
// }

Manager::Manager() {
  // need to preload methods that we do no want to trace
  // use RTLD_NOW to try and force it to resolve the symbols address rather than delaying
  void *dlh = dlopen(NULL, RTLD_NOW);
  for(int i = 0; avoid_inlining_methods[i] != NULL; i++) {
    void *addr = dlsym(dlh, avoid_inlining_methods[i]);
    assert(addr);
    no_trace_methods.insert(addr);
  }
  dlclose(dlh);

}

uint32_t Manager::get_thread_id() {
  if(this_thread_id == 0) {
    this_thread_id = ++thread_id_counter;
  }
  return this_thread_id;
}

void* Manager::begin_trace(void *id, void *ret_addr) {

  void *ret;
  Tracer *l;
  {
    assert(tracer == nullptr);
    branch_info *info = &branches[id];
    assert(info->tracer == nullptr);
    auto buff = make_shared<CodeBuffer>(4 * 1024 * 1024);
    l = tracer = new Tracer(buff);
    l->tracing_from = (mem_loc_t)ret_addr;
    l->owning_thread = get_thread_id();
    // int r = mprotect(this, 4*1024, PROT_READ | PROT_WRITE);
    // assert(!r);
    info->tracer = l;


    // r = mprotect(this, 4*1024, PROT_NONE);
    // assert(!r);

    trace_id = id;
    ret = l->Start(ret_addr);
    is_traced = true;
    info->starting_point = l->get_loop_location();
  }

  return ret;
}

void* Manager::end_trace(void *id) {
  Tracer *l;
  void *ret;
  {
    branch_info *info = &branches[id];
    assert(id == trace_id);
    //if(tracer) {
    //trace[id] = tracer;
    assert(tracer == info->tracer);
    l = tracer;
    ret = l->EndTraceFallThrough();
    trace_id = nullptr;
    is_traced = false;
    info->starting_point = l->get_loop_location();
    l->tracing_from.store(0);
  }
  return ret;
}

void* Manager::jump_to_trace(void *id) {
  //void *addr = trace[id]->get_address();
  assert(0);
}

void* Manager::backwards_branch(void *id, void *ret_addr) {
  if(is_traced) {
    if(id == trace_id) {
      return tracer->EndTraceLoop();
    } else {
      // then we should make a new tracer and jump to that
      return begin_trace(id, ret_addr);
    }
  } else {

    branch_info *info = &branches[id];

    if(info->tracer != nullptr) {
      // there is already a tracer with some other thread running on this item
      // which means that we are going to wait for that thread to finish its trace
      // TODO: make this use atomics

      // TODO: if this aborted, then need to make this have written the resume block at the bottom and
      assert(!info->tracer->did_abort);
      return NULL;
    }
    // if the tracer is null then it either isn't being traced, hasn't started yet or has already finished
    if(info->starting_point != nullptr) {
      // with tracer == null and starting not null then we have already finished this trace so jump to it
      return info->starting_point;
    }
    // don't care about atomic since we are just trying to get an estimate, so if we lose some counts it is fine
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
      branch_info *info = &branches[id];
      void *ret;
      Tracer *l = tracer;
      ret = l->EndTraceFallThrough();
      is_traced = false;
      trace_id = nullptr;
      //info->starting_point = l->get_loop_location();
      info->tracer = nullptr;
      //l->tracing_from.store(0);
      return ret;
    }
  }
  return NULL;
}

void* Manager::temp_disable() {
  if(is_traced) {
    return tracer->TempDisableTrace();
  } else {
    if(is_temp_disabled) {
      ::perror("calling redmagic_temp_disable when the jit is already disabled");
      ::exit(1);
    }
    is_temp_disabled = true;
  }
  return NULL;
}

void* Manager::temp_enable(void *resume_pc) {
  void *r = temp_disable_resume;
  if(r != nullptr) {
    temp_disable_resume = nullptr;
    if(is_traced) {
      tracer->TempEnableTrace(resume_pc);
    }
    return r;
  }
  assert(!is_traced);
  if(!is_temp_disabled) {
    ::perror("calling redmagic_temp_enable when jit is already enabled");
    ::exit(1);
  }
  is_temp_disabled = false;
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

  if(no_trace_methods.find(id) != no_trace_methods.end())
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
