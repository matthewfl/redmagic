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

extern "C" void redmagic_start() {
  if(manager != nullptr) {
    perror("redmagic_start called twice");
    ::exit(1);
  }
  redmagic::manager = new Manager();
}

extern "C" void redmagic_backwards_branch(void *id) {
  manager->backwards_branch(id);
}

extern "C" void redmagic_force_begin_trace(void *id) {
  manager->begin_trace(id);
}

extern "C" void redmagic_force_end_trace(void *id) {
  manager->end_trace(id);
}

extern "C" void redmagic_force_jump_to_trace(void *id) {
  manager->jump_to_trace(id);
}

extern "C" void redmagic_fellthrough_branch(void *id) {
  assert(0);
}

extern "C" void redmagic_ensure_not_traced() {
  assert(0);
}


Manager::Manager() {

}

void Manager::begin_trace(void *id) {
  assert(tracer == nullptr);

  auto buff = make_shared<CodeBuffer>(4 * 1024 * 1024);
  tracer = new Tracer(buff);
  trace_id = id;
  is_traced = true;

  tracer->Start();

}

void Manager::end_trace(void *id) {
  if(tracer) {
    assert(id == trace_id);
    trace[id] = tracer;
    tracer = nullptr;
    trace_id = nullptr;
    is_traced = false;
  }
}

void Manager::jump_to_trace(void *id) {
  //void *addr = trace[id]->get_address();
}

void Manager::backwards_branch(void *id) {
  if(is_traced) {
    if(id == trace_id) {

    }
  } else {
    int cnt = branch_count[id]++;
    if(cnt > 10) {
      begin_trace(id);
    }
  }
}

void Manager::fellthrough_branch(void *id) {
  if(trace_id == id) {
    if(is_traced) {
      end_trace(id);
    }
  }
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

  Dl_info dlinfo;
  if(dladdr(id, &dlinfo) && dlinfo.dli_fbase == self_dlinfo.dli_fbase) {
    no_trace_methods.insert(id);
    return false;
  }

  return true;
}
