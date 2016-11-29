#include "jit_internal.h"
#include "tracer.h"

#include <dlfcn.h>
#include <stdlib.h>

#include <algorithm>

#include "build_version.h"

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

  // this isn't using the real malloc so it might have been allocated with the thread local buffer..
  thread_local vector<tracer_stack_state> threadl_tracer_stack;

  thread_local uint32_t this_thread_id = 0;

  thread_local int32_t branchable_frame_id = -1;

#ifdef CONF_ESTIMATE_INSTRUCTIONS
  thread_local uint64_t last_thread_instructions = 0;
  thread_local uint64_t num_instructions_add = 0;
#endif

#ifdef CONF_GLOBAL_ABORT
  extern long global_icount_abort;
#endif

  extern long global_icount;
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
    assert(protected_malloc == false);
    protected_malloc = pstate;
  }
};


extern "C" void* red_user_force_begin_trace(void *id, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->begin_trace(id, ret_addr);
}

extern "C" void* red_user_force_end_trace(void *id, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->end_trace(id, ret_addr);
}

extern "C" void* red_user_force_jump_to_trace(void *id, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->jump_to_trace(id);
}

extern "C" void* red_user_backwards_branch(void *id, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->backwards_branch(id, ret_addr, stack_ptr);
}

extern "C" void* red_user_fellthrough_branch(void *id, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->fellthrough_branch(id, ret_addr, stack_ptr);
}

extern "C" void* red_user_ensure_not_traced(void *_, void *ret_addr, void **stack_ptr) {
  return manager->ensure_not_traced();
}

extern "C" void* red_user_temp_disable(void *_, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->temp_disable(ret_addr);
  //return NULL;
}

extern "C" void* red_user_is_traced(void *_, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->is_traced_call();
}

extern "C" void* red_user_temp_enable(void *_, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->temp_enable(ret_addr);
  //assert(0);
  //return NULL;
}

extern "C" void* red_user_begin_merge_block(void *_, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->begin_merge_block();
}

extern "C" void* red_user_end_merge_block(void *_, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  return manager->end_merge_block();
}

extern "C" void* red_user_begin_branchable_frame(uint64_t *frame_id, void *ret_addr) {
  UnprotectMalloc upm;
  branchable_frame_id++;
#ifndef NDEBUG
  if(frame_id != NULL) {
    *frame_id = 0xdead0000 | branchable_frame_id;
  }
#endif
  return NULL;
}

extern "C" void* red_user_end_branchable_frame(uint64_t *frame_id, void *ret_addr, void **stack_ptr) {
  UnprotectMalloc upm;
  // TODO: less of a hack, issue when call multiple times in a row
#ifndef NDEBUG
  if(frame_id != NULL && (void**)frame_id - stack_ptr > 0) {
    assert(*frame_id == 0xdead0000 | branchable_frame_id);
  }
#endif
  return manager->end_branchable_frame(ret_addr, stack_ptr);
}

extern "C" void *__real_malloc(size_t);

#pragma GCC visibility push(default)

extern "C" void redmagic_start() {
  UnprotectMalloc upm;
  red_printf("Using redmagic jit by Matthew Francis-Landau <matthew@matthewfl.com> version: " RED_BUILD_VERSION "\n");
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

#pragma GCC visibility pop

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

  // should be no point to inline pthread
  // and likely has some wonky controlflow internally
  "pthread_create",
  "pthread_exit",
  "pthread_join",
  "pthread_tryjoin_np",
  "pthread_timedjoin_np",
  "pthread_detach",
  "pthread_attr_init",
  "pthread_attr_destroy",
  "pthread_attr_getdetachstate",
  "pthread_attr_setdetachstate",
  "pthread_attr_getguardsize",
  "pthread_attr_setguardsize",
  "pthread_attr_getschedparam",
  "pthread_attr_setschedparam",
  "pthread_attr_getschedpolicy",
  "pthread_attr_setschedpolicy",
  "pthread_attr_getinheritsched",
  "pthread_attr_setinheritsched",
  "pthread_attr_getscope",
  "pthread_attr_setscope",
  "pthread_attr_getstackaddr",
  "pthread_attr_setstackaddr",
  "pthread_attr_getstacksize",
  "pthread_attr_setstacksize",
  "pthread_attr_getstack",
  "pthread_attr_setaffinity_np",
  "pthread_attr_getaffinity_np",
  "pthread_getattr_default_np",
  "pthread_setattr_default_np",
  "pthread_getattr_np",
  "pthread_setschedparam",
  "pthread_getschedparam",
  "pthread_setschedprio",
  "pthread_getname_np",
  "pthread_setname_np",
  "pthread_getconcurrency",
  "pthread_setconcurrency",
  "pthread_yield",
  "pthread_setaffinity_np",
  "pthread_getaffinity_np",
  "pthread_once",
  "pthread_setcancelstate",
  "pthread_setcanceltype",
  "pthread_cancel",
  "pthread_testcancel",
  "pthread_cleanup_pop",
  "pthread_cleanup_push",
  "pthread_cleanup_pop",
  "pthread_cleanup_push_defer_np",
  "pthread_cleanup_pop_restore_np",
  "__pthread_cleanup_frame",
  "pthread_cleanup_pop",
  "pthread_cleanup_push",
  "__pthread_cleanup_routine",
  "pthread_cleanup_pop",
  "pthread_cleanup_push_defer_np",
  "__pthread_cleanup_routine",
  "pthread_cleanup_pop_restore_np",
  "pthread_cleanup_pop",
  "pthread_cleanup_push",
  "__pthread_register_cancel",
  "pthread_cleanup_pop",
  "__pthread_unregister_cancel",
  "pthread_cleanup_push_defer_np",
  "__pthread_register_cancel_defer",
  "pthread_cleanup_pop_restore_np",
  "__pthread_unregister_cancel_restore",
  "__pthread_unwind_next",
  "pthread_mutex_init",
  "pthread_mutex_destroy",
  "pthread_mutex_trylock",
  "pthread_mutex_lock",
  "pthread_mutex_timedlock",
  "pthread_mutex_unlock",
  "pthread_mutex_getprioceiling",
  "pthread_mutex_setprioceiling",
  "pthread_mutex_consistent",
  "pthread_mutex_consistent_np",
  "pthread_mutexattr_init",
  "pthread_mutexattr_destroy",
  "pthread_mutexattr_getpshared",
  "pthread_mutexattr_setpshared",
  "pthread_mutexattr_gettype",
  "pthread_mutexattr_settype",
  "pthread_mutexattr_getprotocol",
  "pthread_mutexattr_setprotocol",
  "pthread_mutexattr_getprioceiling",
  "pthread_mutexattr_setprioceiling",
  "pthread_mutexattr_getrobust",
  "pthread_mutexattr_getrobust_np",
  "pthread_mutexattr_setrobust",
  "pthread_mutexattr_setrobust_np",
  "pthread_rwlock_init",
  "pthread_rwlock_destroy",
  "pthread_rwlock_rdlock",
  "pthread_rwlock_tryrdlock",
  "pthread_rwlock_timedrdlock",
  "pthread_rwlock_wrlock",
  "pthread_rwlock_trywrlock",
  "pthread_rwlock_timedwrlock",
  "pthread_rwlock_unlock",
  "pthread_rwlockattr_init",
  "pthread_rwlockattr_destroy",
  "pthread_rwlockattr_getpshared",
  "pthread_rwlockattr_setpshared",
  "pthread_rwlockattr_getkind_np",
  "pthread_rwlockattr_setkind_np",
  "pthread_cond_init",
  "pthread_cond_destroy",
  "pthread_cond_signal",
  "pthread_cond_broadcast",
  "pthread_cond_wait",
  "pthread_cond_timedwait",
  "pthread_condattr_init",
  "pthread_condattr_destroy",
  "pthread_condattr_getpshared",
  "pthread_condattr_setpshared",
  "pthread_condattr_getclock",
  "pthread_condattr_setclock",
  "pthread_spin_init",
  "pthread_spin_destroy",
  "pthread_spin_lock",
  "pthread_spin_trylock",
  "pthread_spin_unlock",
  "pthread_barrier_init",
  "pthread_barrier_destroy",
  "pthread_barrier_wait",
  "pthread_barrierattr_init",
  "pthread_barrierattr_destroy",
  "pthread_barrierattr_getpshared",
  "pthread_barrierattr_setpshared",
  "pthread_key_create",
  "pthread_key_delete",
  "pthread_getspecific",
  "pthread_setspecific",
  "pthread_getcpuclockid",
  "pthread_atfork",



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
  "redmagic_begin_branchable_frame",
  "redmagic_end_branchable_frame",
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
    //assert(addr);
    if(addr)
      no_trace_methods.insert(addr);
  }
  dlclose(dlh);

  get_tracer_head();
}

Manager::~Manager() {
#ifdef CONF_VERBOSE
  red_printf("Manager::~Manager\n");
#endif
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
  assert(0); // TODO: rewrite this method
  return NULL;

  // branch_info *info = &branches[id];
  // if(info->disabled)
  //   return NULL; // do not trace this loop

  // auto old_head = get_tracer_head();

  // void *trace_pc = ret_addr;

  // void *ret;
  // Tracer *l;
  // {
  //   // assert(old_head->tracer == nullptr); // TODO: in the future allow for nesting tracers, since there might be an inner loop
  //   if(old_head->tracer) {
  //     if(old_head->tracer->did_abort) {
  //       red_printf("won't subtrace since there was an abort\n");
  //     } else {
  //       assert(old_head->resume_addr == nullptr);
  //       old_head->tracer->JumpToNestedLoop(id);
  //       trace_pc = (void*)old_head->tracer->get_pc();
  //       assert(old_head->resume_addr != nullptr);
  //     }
  //   }
  //   auto new_head = push_tracer_stack();

  //   //assert(tracer == nullptr);
  //   assert(info->tracer == nullptr || info->tracer->did_abort);
  //   assert(info->starting_point == nullptr);

  //   //auto buff = make_shared<CodeBuffer>(4 * 1024 * 1024);
  //   auto buff = CodeBuffer::CreateBuffer(1024 * 1024);
  //   new_head->tracer = l = new Tracer(buff);
  //   l->tracing_from = (mem_loc_t)trace_pc;
  //   l->owning_thread = get_thread_id();
  //   l->owning_frame_id = branchable_frame_id;
  //   // int r = mprotect(this, 4*1024, PROT_READ | PROT_WRITE);
  //   // assert(!r);
  //   info->tracer = l;


  //   // r = mprotect(this, 4*1024, PROT_NONE);
  //   // assert(!r);

  //   new_head->trace_id = id;
  //   ret = l->Start(trace_pc);
  //   new_head->is_traced = true;
  //   assert(info->trace_loop_counter == nullptr);
  //   info->starting_point = l->get_start_location();
  //   info->trace_loop_counter = l->get_loop_counter();
  // }
  // //return NULL;
  // return ret;
}

extern "C" void* red_end_trace(mem_loc_t);

void* Manager::end_trace(void *id, void *ret_addr) {
  assert(0); // TODO: rewrite this method

  return NULL;

  // void *ret;
  // Tracer *l;
  // auto head = get_tracer_head();
  // branch_info *info = &branches[id];
  // if(!head->tracer /*|| head->did_abort*/) {
  //   // then we weren't actually running on the tracer
  //   return red_end_trace((mem_loc_t)ret_addr);
  // }
  // assert(!info->disabled);
  // assert(head->trace_id == id);
  // assert(head->tracer == info->tracer);
  // l = head->tracer;

  // // poping of the head will tracer stack will be taken care of by the tracer
  // // ret is going to be the address of the normal execution
  // ret = l->EndTraceFallthrough();
  // //l->tracing_from.store(0); // not needed

  // info->tracer = head->tracer = nullptr;

  // Tracer *expected = nullptr;
  // if(!free_tracer_list.compare_exchange_strong(expected, l)) {
  //   // failled to save the tracer to the free list head
  //   delete l;
  // }


  // //return NULL;
  // return ret;
}

void* Manager::jump_to_trace(void *id) {
  //void *addr = trace[id]->get_address();
  assert(0);
  return NULL;
}

void* Manager::backwards_branch(void *id, void *ret_addr, void **stack_ptr) {
  // ignore
  if(id == nullptr)
    return NULL;

  assert(branchable_frame_id >= 0);

  tracer_stack_state* head = get_tracer_head();
  tracer_stack_state* new_head = nullptr;
  Tracer *l;
  void* start_addr = ret_addr;
  auto info = &branches[id];
  if(head->trace_id == id && head->frame_id == branchable_frame_id) {
    if(head->is_traced) {
      assert(!info->disabled);
#ifdef CONF_GLOBAL_ABORT
      //assert(!head->did_abort);
#endif
      assert(!head->is_compiled);
      assert(info->tracer == head->tracer);
      assert(!info->disabled);
      void *ret = head->tracer->EndTraceLoop();
      head->is_compiled = true;
      l = head->tracer;
      head->tracer = info->tracer = nullptr;

      Tracer *expected = nullptr;
      if(!free_tracer_list.compare_exchange_strong(expected, l)) {
        // failled to save the tracer to the free list head
        delete l;
      }

      return ret;
    } else {
      new_head = head;
#ifdef CONF_ESTIMATE_INSTRUCTIONS
      head->num_backwards_loops++;
      if(head->num_backwards_loops > (info->count / 8) || (head->num_backwards_loops > 2 && info->avg_observed_instructions == 0)) {
        uint64_t icnt = instruction_cnt();
        info->avg_observed_instructions = (icnt - head->instruction_cnt_at_start - head->sub_frame_num_instructions) / head->num_backwards_loops;
      }
#endif
      if(info->starting_point && (!info->tracer || info->tracer->did_abort)) {
        // then we must have performed the abort
        //assert(info->tracer->did_abort);
        head->is_traced = true;
        head->is_compiled = true;
        //head->tracer = info->tracer;
        return info->starting_point;
      }
      goto check_new_trace;
    }
  } else {
    // if there is no tracer set then that means that this was either call directly from normal code
    // and the ret_addr is a valid starting point, or this is call from branch_to_sub_trace which
    // will pass in a valid address to the ret_addr
    if(head->tracer) {
      //assert(head->tracer);
      start_addr = (void*)head->tracer->get_pc();
      head->tracer->JumpToNestedLoop(id);
    }
    new_head = push_tracer_stack();
    new_head->frame_stack_ptr = (mem_loc_t)stack_ptr;
    head = &threadl_tracer_stack[threadl_tracer_stack.size() - 2];
    if(head->tracer) {
      new_head->return_to_trace_when_done = true;
    }
    new_head->trace_id = id;
    if(info->starting_point) {
      info->count++;
      if(info->tracer && !info->tracer->did_abort) {
        // then this must be some recursive frame or another thread is tracing this
#ifndef NDEBUG
        if(info->tracer->owning_thread == get_thread_id()) {
          // this is a recursive frame
          for(int i = threadl_tracer_stack.size() - 2; i >= 0; i--) {
            if(threadl_tracer_stack[i].trace_id == id) {
              // we found this that was tracing from
              assert(threadl_tracer_stack[i].frame_id != branchable_frame_id);
              return start_addr;
            }
          }
          assert(0);
        }
#endif
        return start_addr;
      }
      new_head->is_compiled = true;
      new_head->is_traced = true;
#ifdef CONF_VERBOSE
      red_printf("entering trace %#016lx\n", id);
#endif
      return info->starting_point;
    }
    goto check_new_trace;
    // int cnt = info->count++;
    // if(cnt > CONF_NUMBER_OF_JUMPS_BEFORE_TRACE) {
    //   goto start_new_trace;
    //   //return begin_trace(id, ret_addr);
    // }
    // return NULL;
  }

 check_new_trace:
  int cnt = info->count++;
  if(info->tracer) {
    // then it aborted or is currently performing this trace
    if(info->tracer->did_abort) {
      new_head->is_compiled = true;
      new_head->is_traced = true;
#ifdef CONF_VERBOSE
      red_printf("entering aborted trace %#016lx\n", id);
#endif
      return info->starting_point;
    }
    return start_addr;
  }
  bool should_perform_trace = cnt > CONF_NUMBER_OF_JUMPS_BEFORE_TRACE &&
    !info->disabled &&
    // to check that it loops a few times once it enters, or that the previous frame is traced
    (cnt > info->count_fellthrough * 3 || head->is_traced);
#ifdef CONF_USE_TIMERS
  timespec now;
  if(clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
    if(info->first_observed_time.tv_sec == 0) {
      info->first_observed_time = now;
    }
    if(time_ms(time_delta(info->first_observed_time, now)) < CONF_TIMER_DELAY_MS) {
      should_perform_trace = false;
    }
  }

#define TRACE_SPEED_LIMIT(time, cnt)            \
  if(time_ms(time_delta(speed_limit_time ## time, now)) >= time)  { \
    speed_limit_time ## time = now;                                 \
    speed_limit_last_icount ## time = global_icount;                \
  } else if(speed_limit_last_icount ## time + cnt < global_icount) { \
    should_perform_trace = false;                                    \
  }

  CONF_TRACE_INSTRUCTION_LIMIT_PER_TIME(TRACE_SPEED_LIMIT)

#undef TRACE_SPEED_LIMIT


#endif
// #ifdef CONF_ESTIMATE_INSTRUCTIONS
//   if(info->avg_observed_instructions == 0) {
//     // if we don't know this number then likely there were a number of fallthroughs
//     // which indicates that the branch doesn't backwards jump a lot
//     should_perform_trace = false;
//   }
// #endif
  if(should_perform_trace) {
    goto start_new_trace;
  }

  return start_addr; // do nothing, force it to jump back to "normal" address even if coming from a tracer

 start_new_trace:
  assert(!info->disabled);
  assert(!info->tracer);
  assert(new_head != nullptr);
  assert(info->trace_loop_counter == nullptr);
  auto buff = CodeBuffer::CreateBuffer(1024 * 1024);
  info->tracer = new_head->tracer = l = new Tracer(buff);
  l->tracing_from = (mem_loc_t)start_addr;
  l->owning_thread = get_thread_id();
  l->owning_frame_id = branchable_frame_id;
  void *ret = l->Start(start_addr);
  new_head->is_traced = true;
  info->starting_point = l->get_start_location();
  info->trace_loop_counter = l->get_loop_counter();

  return ret;

}

void* Manager::fellthrough_branch(void *id, void *ret_addr, void **stack_ptr) {
  // ignore
  if(id == nullptr)
    return NULL;

  Tracer *l;
  void *ret = NULL;
  auto head = get_tracer_head();
  if(head->trace_id == id && head->frame_id == branchable_frame_id) {
    auto info = &branches[id];
    info->count_fellthrough++;
    if(head->is_traced) {
      assert(!head->is_compiled);
      assert(!info->disabled);
      assert(head->tracer && head->tracer == info->tracer);
      l = head->tracer;
      // this will pop the head of the stack internally
      ret = l->EndTraceFallthrough();
      // the tracer ^^^ will delete itself

      info->tracer = head->tracer = nullptr;

      // Tracer *expected = nullptr;
      // if(!free_tracer_list.compare_exchange_strong(expected, l)) {
      //   // failled to save the tracer to the free list head
      //   delete l;
      // }

      return ret;
    } else {
      assert(!head->is_compiled);
      assert(head->resume_addr == nullptr);
      assert(head->is_temp_disabled == false);
      // we have to pop this frame since we weren't being traced and there is nothing that will do it for us
      auto old_head = pop_tracer_stack();
      auto new_head = get_tracer_head();
      ((mem_loc_t*)stack_ptr)[-1] = old_head.frame_stack_ptr - (mem_loc_t)stack_ptr;
      if(new_head->resume_addr) {
        assert(old_head.return_to_trace_when_done);
        if(new_head->tracer) {
          // ret_addr will not be a traced address but a real normal address
          // so we set that as the possible resume address if there is a tracer that we are going to be resuming
          new_head->tracer->JumpFromNestedLoop(ret_addr);
        }
        ret = new_head->resume_addr;
        new_head->resume_addr = nullptr;
        return ret;
      }
      return NULL;
    }
  }

  if(head->tracer) {
    // there is a fallthrough without a backwards branch which means that we never
    // got to the backwards branch portion of this loop
    // assert(!head->is_compiled);
    // assert(head->tracer);
    if(head->frame_id == branchable_frame_id) {
      return head->tracer->CheckNotSelfFellthrough();
    } else {
      // if this is at a different level in the branchable frame then it can't possible be the same instance
      // and the check self will only check the id not the branchable depth
      return head->tracer->DeleteLastCall((void*)&redmagic_fellthrough_branch);
    }
  }

  assert(!head->is_compiled || head->frame_id != branchable_frame_id);

  return NULL;
}

void* Manager::temp_disable(void *ret_addr) {
  temp_disable_last_addr = ret_addr;
  auto head = get_tracer_head();
  assert(!head->is_temp_disabled);

  //head->d_ret = ret_addr;
  void *ret = NULL;

  //assert(!head->is_traced || head->tracer);
  // ^^^ due to the tracer sometimes

  if(head->tracer && !head->tracer->did_abort) {
    // this will push the stack
    ret = head->tracer->TempDisableTrace();
  } else {
    assert(!head->resume_addr);
    head->is_temp_disabled = true;
    push_tracer_stack();
  }
  return ret;
}

void* Manager::temp_enable(void *ret_addr) {
  // have this here so that we can have pop double check that a frame is not disabled when poped
  assert(threadl_tracer_stack[threadl_tracer_stack.size() - 2].is_temp_disabled);
  threadl_tracer_stack[threadl_tracer_stack.size() - 2].is_temp_disabled = false;

  auto old_head = pop_tracer_stack();
  auto head = get_tracer_head();
  //assert(head->is_temp_disabled);
  //head->is_temp_disabled = false;
  void *ret = NULL;
  //head->d_ret = nullptr;
  if(old_head.return_to_trace_when_done && head->tracer && !head->tracer->did_abort) {
    head->tracer->TempEnableTrace(ret_addr);
  }
  if(head->resume_addr != nullptr) {
    assert(old_head.return_to_trace_when_done);
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
  auto info = &branches[id];
  info->disabled = true;
  for(int i = 0; i < threadl_tracer_stack.size(); i++) {
    auto b = &threadl_tracer_stack[i];
    assert(b->trace_id != id || !b->is_traced);
  }
}

void* Manager::ensure_not_traced() {
  auto head = get_tracer_head();
  if(head->is_traced) {
    if(head->is_compiled) {
      // must be in the context of a not traced function
      // which doesn't have any external viewable info (except maybe ret addr doesn't point to some code buffer.....)
      return NULL;
    }
    auto info = &branches[head->trace_id];
    Tracer *l = head->tracer;
    assert(info->tracer == head->tracer);
    void *ret = l->EndTraceEnsure();
    if(ret == NULL) {
      // this must be a not inlined function which is fine I guess?
      return NULL;
    }
    info->tracer = head->tracer = nullptr;

    Tracer *expected = nullptr;
    if(!free_tracer_list.compare_exchange_strong(expected, l)) {
      // failled to save the tracer to the free list head
      delete l;
    }

    return ret;
  }
  assert(!head->is_temp_disabled);
  // if(head->trace_id) {
  //   auto info = &branches[head->trace_id];
  //   info->disabled = true;
  // }
  return NULL;
}

void* Manager::end_branchable_frame(void *ret_addr, void **stack_ptr) {
  auto head = get_tracer_head();
#ifdef CONF_ALLOW_UNCLOSED_TRACES
  // check if the current trace should be finished out
  // if so, have it fallthrough and then run the corresponding block of code
  // if there are multiple traces then this method will end up getting call once per each trace that needs to be cleaned up
  // assert that this return address actually came from a call instead of a tail optimized jmp, b/c life is bad...
  assert(head->is_traced || ((uint8_t*)ret_addr)[-5] == 0xE8);
  assert(ret_addr == *stack_ptr);
  while(head->frame_id >= branchable_frame_id) {
    assert(!head->is_compiled);
    assert(!head->is_temp_disabled);
    if(head->is_traced) {
      auto info = &branches[head->trace_id];
      assert(info->tracer == head->tracer);
      Tracer *l = head->tracer;
      // poping off the stack and possibly resuming the next tracer will be handled inside of this
      void *ret = l->EndTraceEndBranchable();
      head->tracer = info->tracer = nullptr;

      Tracer *expected = nullptr;
      if(!free_tracer_list.compare_exchange_strong(expected, l)) {
        // failled to save the tracer to the free list head
        delete l;
      }

      // this method will get call again with this current frame poped
      return ret;
    } else {
      if(head->trace_id != nullptr) {
        auto info = &branches[head->trace_id];
        info->count_fellthrough++;
      }
      auto old_head = pop_tracer_stack();
      head = get_tracer_head();

      if(head->resume_addr) {
        // assert that this is a call instruction
        assert(((uint8_t*)ret_addr)[-5] == 0xE8);
        assert(old_head.return_to_trace_when_done);

        if(head->tracer) {
          head->tracer->JumpFromNestedLoop((uint8_t*)ret_addr - 5); // backup the pc to the call instruction
        }
        // reset what the stack has the return address as since when resuming the trace it will check that the "normal" rip is the same as where
        // it expects to start
        *stack_ptr = (uint8_t*)ret_addr - 5;
        void *ret = head->resume_addr;
        head->resume_addr = nullptr;
        return ret;
      }
    }
  }
#endif
  assert(head->frame_stack_ptr >= (mem_loc_t)stack_ptr);
  branchable_frame_id--;
  assert(head->frame_id <= branchable_frame_id);
  return NULL;
}

uint32_t Manager::tracer_stack_size() {
  return threadl_tracer_stack.size();
}

tracer_stack_state* Manager::push_tracer_stack() {
  tracer_stack_state e;
  e.frame_id = branchable_frame_id;
#ifdef CONF_ESTIMATE_INSTRUCTIONS
  e.instruction_cnt_at_start = instruction_cnt();
#endif
  threadl_tracer_stack.push_back(e);
  return stack_head = &threadl_tracer_stack.back();
}

tracer_stack_state Manager::pop_tracer_stack() {
  auto r = threadl_tracer_stack.back();
  assert(r.frame_id == branchable_frame_id);
  threadl_tracer_stack.pop_back();
  assert(!threadl_tracer_stack.empty());
  stack_head = &threadl_tracer_stack.back();
  assert(!stack_head->is_temp_disabled);
#ifdef CONF_ESTIMATE_INSTRUCTIONS
  uint64_t icnt = instruction_cnt();
  uint64_t sub_f = icnt  - r.instruction_cnt_at_start;
  stack_head->sub_frame_num_instructions += sub_f;
#endif

  // for(;;) {
  //   if(stack_head->trace_id) {
  //     auto info = &branches[stack_head->trace_id];
  //     if(info->disabled) {
  //       assert(0);
  //       continue;
  //     }
  //   }
  //   break;
  // }
  return r;
}

tracer_stack_state *Manager::get_tracer_head() {
  if(stack_head == nullptr) {
    assert(threadl_tracer_stack.capacity() == 0);
    threadl_tracer_stack.reserve(50);
    // tracer_stack_state e;
    // threadl_tracer_stack.push_back(e);
    push_tracer_stack();
    //    stack_head = &threadl_tracer_stack[0];
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
      if(manager) {
        // this is at the end of the program so don't print this jumk
        threadl_tracer_stack.clear();
        manager->print_info();
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


void Manager::print_info() {
  UnprotectMalloc upm;
  vector<pair<void*, branch_info*>> bi;
  bi.reserve(branches.size());
  for(auto it = branches.begin(); it != branches.end(); it++) {
    bi.push_back(make_pair(it->first, &it->second));
  }
  std::sort(bi.begin(), bi.begin() + bi.size(), [](auto a, auto b) -> bool {
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
      red_printf("%3s|%16s|%16s|%10s|%10s|%10s|%10s|%10s|%12s|%10s"
#ifdef CONF_ESTIMATE_INSTRUCTIONS
                 "|%14s"
#endif
                 "\n", "#", "trace id", "trace location", "loop count", "enter cnt", "exit cnt", "sum icount", "max icount", "sub branches", "fin traces"
#ifdef CONF_ESTIMATE_INSTRUCTIONS
                 ,"esti instr"
#endif
                 );
      red_printf("===============================================================================================================================\n");
    }
    cnt++;
    if(cnt > 200) break;
    red_printf("%3i|%#016lx|%#016lx|%10lu|%10lu|%10lu|%10lu|%10lu|%12i|%10i"
#ifdef CONF_ESTIMATE_INSTRUCTIONS
               "|%14lu"
#endif
               "\n",
               cnt,
               b.first,
               b.second->starting_point,
               (b.second->trace_loop_counter ? *b.second->trace_loop_counter : 0),
               b.second->count,
               b.second->count_fellthrough,
               b.second->traced_instruction_count,
               b.second->longest_trace_instruction_count,
               b.second->sub_branches,
               b.second->finish_traces
#ifdef CONF_ESTIMATE_INSTRUCTIONS
               ,b.second->avg_observed_instructions
#endif
               );
  }

  red_printf("thread tracers\n");
  red_printf("%3s|E|C|%16s|%16s|%16s|%16s|%12s"
#ifdef CONF_ESTIMATE_INSTRUCTIONS
             "|%14s"
#endif
             "\n"
             , "#", "trace id", "tracing from", "tracing pc", "generated pc", "trace icount"
#ifdef CONF_ESTIMATE_INSTRUCTIONS
             ,"esti instr"
#endif
             );
#ifdef CONF_ESTIMATE_INSTRUCTIONS
  uint64_t current_instructions = instruction_cnt();
  uint64_t sub_frame_instructions = 0;
#endif
  red_printf("=======================================================================================================\n");
  for(int i = threadl_tracer_stack.size() - 1; i >= 0; i--) {
    auto info = &threadl_tracer_stack[i];
    red_printf("%3i|%1i|%1i|%#016lx|%#016lx|%#016lx|%#016lx|%12lu"
#ifdef CONF_ESTIMATE_INSTRUCTIONS
               "|%14lu"
#endif
               "\n",
               i,
               (info->tracer && !info->is_temp_disabled),
               info->is_compiled,
               info->trace_id,
               info->tracer ? (mem_loc_t)info->tracer->tracing_from : 0,
               info->tracer ? info->tracer->get_pc() : 0,
               info->tracer ? info->tracer->generated_pc() : 0,
               info->tracer ? info->tracer->get_icount() : 0
#ifdef CONF_ESTIMATE_INSTRUCTIONS
               ,(current_instructions - info->instruction_cnt_at_start - info->sub_frame_num_instructions - sub_frame_instructions)
#endif
               );
#ifdef CONF_ESTIMATE_INSTRUCTIONS
    sub_frame_instructions = current_instructions - info->instruction_cnt_at_start;
#endif

  }
}
