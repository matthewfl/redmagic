#include "jit_internal.h"
#include "tracer.h"

#include <dlfcn.h>
#include <stdlib.h>

#include <algorithm>

using namespace redmagic;
using namespace std;

namespace redmagic {
  //thread_local bool is_traced = false;
  //thread_local bool is_temp_disabled = false;
  thread_local void *temp_disable_last_addr = nullptr; // for debuggging
  //thread_local void *temp_disable_resume = nullptr;
  //thread_local bool is_running_compiled = false;

  thread_local bool protected_malloc = true;

  Manager *manager = nullptr;

  //thread_local Tracer* tracer = nullptr;
  //thread_local void* trace_id = nullptr;

  std::atomic<Tracer*> free_tracer_list;

  thread_local tracer_stack_state *stack_head = nullptr;

  thread_local vector<tracer_stack_state> threadl_tracer_stack;

  thread_local uint32_t this_thread_id = 0;

#ifdef CONF_GLOBAL_ABORT
  extern long global_icount_abort;
#endif
}

class UnprotectMalloc {
private:
  bool pstate;
public:
  UnprotectMalloc() {
    pstate = protected_malloc;
    protected_malloc = false;
  }
  ~UnprotectMalloc() {
    protected_malloc = pstate;
  }
};


extern "C" void* red_user_force_begin_trace(void *id, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->begin_trace(id, ret_addr);
}

extern "C" void* red_user_force_end_trace(void *id, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->end_trace(id, ret_addr);
}

extern "C" void* red_user_force_jump_to_trace(void *id, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->jump_to_trace(id);
}

extern "C" void* red_user_backwards_branch(void *id, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->backwards_branch(id, ret_addr);
}

extern "C" void* red_user_fellthrough_branch(void *id, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->fellthrough_branch(id, ret_addr);
}

extern "C" void* red_user_ensure_not_traced(void *_, void *ret_addr) {
  // TODO:
  auto head = manager->get_tracer_head();
  assert(!head->is_traced || head->did_abort); // TODO: better manage abort
  return NULL;
}

extern "C" void* red_user_temp_disable(void *_, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->temp_disable(ret_addr);
  //return NULL;
}

extern "C" void* red_user_is_traced(void *_, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->is_traced_call();
}

extern "C" void* red_user_temp_enable(void *_, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->temp_enable(ret_addr);
  //assert(0);
  //return NULL;
}

extern "C" void* red_user_begin_merge_block(void *_, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->begin_merge_block();
}

extern "C" void* red_user_end_merge_block(void *_, void *ret_addr) {
  UnprotectMalloc upm;
  return manager->end_merge_block();
}

extern "C" void *__real_malloc(size_t);

extern "C" void redmagic_start() {
  UnprotectMalloc upm;
  red_printf("Using redmagic jit by Matthew Francis-Landau <matthew@matthewfl.com>\n");
  if(manager != nullptr) {
    red_printf("redmagic_start called twice");
    abort();
  }
  //void *p = __real_malloc(sizeof(Manager) + 1024*12);
  //p = (void*)((((mem_loc_t)p) + 8*1024) & ~(0xfff));

  redmagic::manager = new Manager();
  // int r = mprotect(p, 4*1024, PROT_NONE);
  // assert(!r);

#ifdef CONF_GLOBAL_ABORT
  char *abort_v = getenv("REDMAGIC_GLOBAL_ABORT");
  if(abort_v)
    redmagic::global_icount_abort = atol(abort_v);
#endif
}

extern "C" void redmagic_do_not_trace_function(void *function_pointer) {
  UnprotectMalloc upm;
  manager->do_not_trace_method(function_pointer);
}

extern "C" void redmagic_disable_branch(void *id) {
  UnprotectMalloc upm;
  manager->disable_branch(id);
}

static const char *avoid_inlining_methods[] = {
  // inlining the allocator doesn't really help since it will have a lot of branching
  // in trying to find where there is open memory
  "malloc",
  "free",
  "cfree", // python is somehow using this?
  "realloc",
  "calloc",
  "exit",
  "abort",

  // we use the dl calls while debugging at least so don't inline them since there might be conflicts
  "dlopen",
  "dlclose",
  "dlsym",
  "dlmopen",
  "dlvsym",
  "dladdr",
  "dladdr1",
  "dlinfo",


  // we don't want to inline ourselves
  // so record the entry functions
  // TODO: don't have to use dladdr to resolve this since they are in the same binary
  "redmagic_force_begin_trace",
  "redmagic_force_end_trace",
  "redmagic_force_jump_to_trace",
  "redmagic_backwards_branch",
  "redmagic_fellthrough_branch",
  "redmagic_ensure_not_traced",
  "redmagic_temp_disable",
  "redmagic_temp_enable",
  "redmagic_is_traced",
  "redmagic_disable_branch",
  "redmagic_do_not_trace_function",
  "redmagic_begin_merge_block",
  "redmagic_end_merge_block",
  NULL,
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

  get_tracer_head();
}

Manager::~Manager() {
  red_printf("Manager::~Manager\n");
}

void Manager::do_not_trace_method(void *addr) {
  no_trace_methods.insert(addr);
}

uint32_t Manager::get_thread_id() {
  if(this_thread_id == 0) {
    this_thread_id = ++thread_id_counter;
  }
  return this_thread_id;
}

void* Manager::begin_trace(void *id, void *ret_addr) {
  branch_info *info = &branches[id];
  if(info->disabled)
    return NULL; // do not trace this loop

  auto old_head = get_tracer_head();

  void *trace_pc = ret_addr;

  void *ret;
  Tracer *l;
  {
    // assert(old_head->tracer == nullptr); // TODO: in the future allow for nesting tracers, since there might be an inner loop
    if(old_head->tracer) {
      if(old_head->tracer->did_abort) {
        red_printf("won't subtrace since there was an abort\n");
      } else {
        assert(old_head->resume_addr == nullptr);
        old_head->tracer->JumpToNestedLoop(id);
        trace_pc = (void*)old_head->tracer->get_pc();
        assert(old_head->resume_addr != nullptr);
      }
    }
    auto new_head = push_tracer_stack();

    //assert(tracer == nullptr);
    assert(info->tracer == nullptr || info->tracer->did_abort);
    assert(info->starting_point == nullptr);

    //auto buff = make_shared<CodeBuffer>(4 * 1024 * 1024);
    auto buff = CodeBuffer::CreateBuffer(1024 * 1024);
    new_head->tracer = l = new Tracer(buff);
    l->tracing_from = (mem_loc_t)trace_pc;
    l->owning_thread = get_thread_id();
    // int r = mprotect(this, 4*1024, PROT_READ | PROT_WRITE);
    // assert(!r);
    info->tracer = l;


    // r = mprotect(this, 4*1024, PROT_NONE);
    // assert(!r);

    new_head->trace_id = id;
    ret = l->Start(trace_pc);
    new_head->is_traced = true;
    assert(info->trace_loop_counter == nullptr);
    info->starting_point = l->get_start_location();
    info->trace_loop_counter = l->get_loop_counter();
  }
  //return NULL;
  return ret;
}

extern "C" void* red_end_trace(mem_loc_t);

void* Manager::end_trace(void *id, void *ret_addr) {
  void *ret;
  Tracer *l;
  auto head = get_tracer_head();
  branch_info *info = &branches[id];
  if(!head->tracer || head->did_abort) {
    // then we weren't actually running on the tracer
    return red_end_trace((mem_loc_t)ret_addr);
  }
  assert(!info->disabled);
  assert(head->trace_id == id);
  assert(head->tracer == info->tracer);
  l = head->tracer;

  // poping of the head will tracer stack will be taken care of by the tracer
  // ret is going to be the address of the normal execution
  ret = l->EndTraceFallthrough();
  //l->tracing_from.store(0); // not needed

  info->tracer = head->tracer = nullptr;

  Tracer *expected = nullptr;
  if(!free_tracer_list.compare_exchange_strong(expected, l)) {
    // failled to save the tracer to the free list head
    delete l;
  }


  //return NULL;
  return ret;
}

void* Manager::jump_to_trace(void *id) {
  //void *addr = trace[id]->get_address();
  assert(0);
  return NULL;
}

void* Manager::backwards_branch(void *id, void *ret_addr) {
  // ignore
  if(id == nullptr)
    return NULL;

  //return NULL;
  auto head = get_tracer_head();
  if(head->is_traced) {
    assert(head->tracer || head->did_abort);
    if(id == head->trace_id) {
      auto info = &branches[id];
#ifdef CONF_GLOBAL_ABORT
      if(head->did_abort) {
        red_printf("starting a previously aborted trace\n");
        return info->starting_point;
      }

      if(head->is_compiled) {
        // then there must have been an abort that has us here
        return info->starting_point;
      }
#endif

      assert(!head->is_compiled);
      assert(head->tracer == info->tracer);
      assert(!info->disabled);
      void *ret = head->tracer->EndTraceLoop();
      head->is_compiled = true;
      Tracer *l = head->tracer;
      info->tracer = head->tracer = nullptr;

      Tracer *expected = nullptr;
      if(!free_tracer_list.compare_exchange_strong(expected, l)) {
        // failled to save the tracer to the free list head
        delete l;
      }

      // We are continuing the loop so there is no need to check the parent stack frame
      //pop_tracer_stack();
      //auto new_head = get_tracer_head();
      //assert(new_head->resume_addr == nullptr); // TODO: handle resuming previous tracer
      return ret;
    } else {
      // then we should make a new tracer and jump to that
      auto info = &branches[id];
      if(info->starting_point) {
        assert(!info->tracer || info->tracer->did_abort); // that we are done with this
        auto new_head = push_tracer_stack();
        if(head->tracer && !head->tracer->did_abort)
          head->tracer->JumpToNestedLoop(id);
        else
          new_head->did_abort = !!head->tracer;
        new_head->is_compiled = true;
        new_head->is_traced = true;
        new_head->trace_id = id;
        return info->starting_point;
      }
      return begin_trace(id, ret_addr);
    }
  } else {
    branch_info *info = &branches[id];

    if(info->disabled) {
      // this loop is disabled
      return NULL;
    }

    if(info->tracer != nullptr) {
      // there is already a tracer with some other thread running on this item
      // which means that we are going to wait for that thread to finish its trace
      // TODO: make this use atomics

      // TODO: if this aborted, then need to make this have written the resume block at the bottom and
      if(info->tracer->did_abort) {
#ifdef CONF_VERBOSE
        red_printf("previous attempt aborted %x\n", id);
#endif
#ifdef CONF_GLOBAL_ABORT
        auto head = push_tracer_stack();
        head->is_compiled = true;
        head->is_traced = true;
        head->trace_id = id;
        head->did_abort = true;
        return info->starting_point;
#endif
      }
      return NULL;
    }
    // if the tracer is null then it either isn't being traced, hasn't started yet or has already finished
    if(info->starting_point != nullptr) {
      // with tracer == null and starting not null then we have already finished this trace so jump to it
      auto head = push_tracer_stack();
      head->is_compiled = true;
      head->is_traced = true;
      head->trace_id = id;
#ifdef CONF_VERBOSE
      red_printf("entering trace %x\n", id);
#endif
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

void* Manager::fellthrough_branch(void *id, void *ret_addr) {
  // ignore
  if(id == nullptr)
    return NULL;

  auto head = get_tracer_head();
  if(head->trace_id == id && head->is_traced) {
    return end_trace(id, ret_addr);
    // branch_info *info = &branches[id];
    // void *ret;
    // Tracer *l = head->tracer;
    // ret = l->EndTraceFallThrough();
    // auto old_head = pop_tracer_stack();
    // auto new_head = get_tracer_head();
    // // TODO: handle how to resume the previous tracer?
    // assert(new_head->resume_addr == nullptr);
    // // is_traced = false;
    // // trace_id = nullptr;
    // //info->starting_point = l->get_loop_location();
    // info->tracer = nullptr;
    // //l->tracing_from.store(0);
    // return ret;
  }
  return NULL;
}

void* Manager::temp_disable(void *resume_pc) {
  temp_disable_last_addr = resume_pc;
  auto head = get_tracer_head();
  assert(!head->is_temp_disabled);
  head->is_temp_disabled = true;
  void *ret = NULL;
  assert(!head->is_traced || head->tracer || head->did_abort);
  if(head->tracer && !head->tracer->did_abort) {
    // this will push the stack
    ret = head->tracer->TempDisableTrace();
  } else {
    push_tracer_stack();
  }
  return ret;
}

void* Manager::temp_enable(void *resume_pc) {
  auto old_head = pop_tracer_stack();
  assert(!old_head.is_temp_disabled);
  auto head = get_tracer_head();
  assert(head->is_temp_disabled);
  head->is_temp_disabled = false;
  void *ret = NULL;
  if(head->tracer && !head->tracer->did_abort) {
    head->tracer->TempEnableTrace(resume_pc);
  }
  if(head->resume_addr != nullptr) {
    ret = head->resume_addr;
    head->resume_addr = nullptr;
  }
  return ret;

  // void *r = temp_disable_resume;
  // if(r != nullptr) {
  //   temp_disable_resume = nullptr;
  //   if(is_traced) {
  //     tracer->TempEnableTrace(resume_pc);
  //   }
  //   return r;
  // }
  // assert(!is_traced);
  // if(!is_temp_disabled) {
  //   red_printf("calling redmagic_temp_enable when jit is already enabled");
  //   abort();
  // }
  // is_temp_disabled = false;
  // return NULL;
}

void* Manager::begin_merge_block() {
  auto head = get_tracer_head();
  if(head->tracer && !head->tracer->did_abort) {
    return head->tracer->BeginMergeBlock();
  }
  return NULL;
}

void* Manager::end_merge_block() {
  auto head = get_tracer_head();
  if(head->tracer && !head->tracer->did_abort) {
    return head->tracer->EndMergeBlock();
  }
  return NULL;
}

void* Manager::is_traced_call() {
  auto head = get_tracer_head();
  if(head->is_traced) {
#ifdef CONF_GLOBAL_ABORT
    if(!head->tracer || head->tracer->did_abort) // this trace got aborted somehow, but still return that we are "in the tracer"
      return (void*)1;
#endif
    return head->tracer->ReplaceIsTracedCall();
  }
  return NULL;
}

void Manager::disable_branch(void *id) {
  branches[id].disabled = true;
  for(int i = 0; i < threadl_tracer_stack.size(); i++) {
    assert(threadl_tracer_stack[i].trace_id != id);
  }
}

uint32_t Manager::tracer_stack_size() {
  return threadl_tracer_stack.size();
}

tracer_stack_state* Manager::push_tracer_stack() {
  tracer_stack_state e;
  threadl_tracer_stack.push_back(e);
  return stack_head = &threadl_tracer_stack.back();
}

tracer_stack_state Manager::pop_tracer_stack() {
  auto r = threadl_tracer_stack.back();
  threadl_tracer_stack.pop_back();
  assert(!threadl_tracer_stack.empty());
  stack_head = &threadl_tracer_stack.back();
  return r;
}

tracer_stack_state *Manager::get_tracer_head() {
  if(stack_head == nullptr) {
    assert(threadl_tracer_stack.capacity() == 0);
    threadl_tracer_stack.reserve(50);
    tracer_stack_state e;
    threadl_tracer_stack.push_back(e);
    stack_head = &threadl_tracer_stack[0];
  }
  return stack_head;
}

namespace {
  Dl_info self_dlinfo;
  static void _nonamef() {}
  struct _noname {
    _noname() {
      if(!dladdr((void*)&_nonamef, &self_dlinfo)) {
        red_printf("failed to get dlinfo for self");
      }
    }
    ~_noname() {
      if(manager)
        manager->print_info();
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

namespace redmagic {
  extern long global_icount;
}

void Manager::print_info() {
  UnprotectMalloc upm;
  vector<pair<void*, branch_info*>> bi;
  bi.reserve(branches.size());
  // for(auto b : branches) {
  //   bi.push_back(&b);
  // }
  for(auto it = branches.begin(); it != branches.end(); it++) {
    bi.push_back(make_pair(it->first, &it->second));
  }
  std::sort(bi.begin(), bi.begin() + bi.size(), [](auto a, auto b) -> bool {
      //return a < b;


      if(a.second->trace_loop_counter != nullptr && b.second->trace_loop_counter != nullptr) {
        if(a.second->longest_trace_instruction_count * (*a.second->trace_loop_counter) > b.second->longest_trace_instruction_count * (*b.second->trace_loop_counter))
          return true;
        else
          return false;
      }
      if(a.second->trace_loop_counter == nullptr && b.second->trace_loop_counter != nullptr)
        return false;
      if(b.second->trace_loop_counter == nullptr && a.second->trace_loop_counter != nullptr)
        return true;

      return a.second->count > b.second->count;

    });

  red_printf("Global icount: %ld\n", global_icount);

  int cnt = 0;
  for(auto b : bi) {
    if(cnt % 30 == 0) {
      red_printf("%3s|%16s|%16s|%10s|%10s|%10s|%12s|%10s\n", "#", "trace id", "trace location", "loop count", "sum icount", "max icount", "sub branches", "finished traces");
      red_printf("=======================================================================================================\n");
    }
    cnt++;
    if(cnt > 200) break;
    red_printf("%3i|%#016lx|%#016lx|%10lu|%10lu|%10lu|%12i|%10i\n",
               cnt,
               b.first,
               b.second->starting_point,
               (b.second->trace_loop_counter ? *b.second->trace_loop_counter : 0),
               b.second->traced_instruction_count,
               b.second->longest_trace_instruction_count,
               b.second->sub_branches,
               b.second->finish_traces);
  }

  red_printf("thread tracers\n");
  red_printf("%3s|E|C|%16s|%16s|%16s|%16s|%16s\n", "#", "trace id", "tracing from", "tracing pc", "generated pc", "trace icount");
  red_printf("=======================================================================================================\n");
  for(int i = threadl_tracer_stack.size() - 1; i >= 0; i--) {
    auto info = &threadl_tracer_stack[i];
    red_printf("%3i|%1i|%1i|%#016lx|%#016lx|%#016lx|%#016lx|%10lu\n",
               i,
               (info->tracer && !info->is_temp_disabled),
               info->is_compiled,
               info->trace_id,
               info->tracer ? (mem_loc_t)info->tracer->tracing_from : 0,
               info->tracer ? info->tracer->get_pc() : 0,
               info->tracer ? info->tracer->generated_pc() : 0,
               info->tracer ? info->tracer->get_icount() : 0);
  }
}
