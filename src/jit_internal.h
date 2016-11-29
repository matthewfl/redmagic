#ifndef REDMAGIC_INTERNAL_H_
#define REDMAGIC_INTERNAL_H_

#include "redmagic.h"

#include "config.h"

#ifndef __cplusplus
#error "require c++ to compile red magic"
#endif

#include <sys/user.h>
#include <sys/reg.h>

#include <string.h>

#include <thread>
#include <atomic>
#include <unordered_map>
#include <vector>
#include <unordered_set>

#include <mutex>

// #include <tbb/concurrent_unordered_set.h>
// #include <tbb/concurrent_unordered_map.h>

#include <errno.h>
#include <memory>
#include <assert.h>

#ifdef CONF_USER_TIMERS
#include <time.h>
#endif

// for write syscall
#include <unistd.h>

#include <udis86.h>

#include "cpp_allocator.h"

namespace redmagic {

  class Manager;
  class CodeBuffer;
  class Tracer;
  class SimpleCompiler;

  typedef decltype(((struct user_regs_struct*)(NULL))->r15) register_t;
  typedef uint64_t mem_loc_t; // a memory location in the debugged program

  struct tracer_stack_state;

  template<typename Key, typename Value>
  using RealMallocMap = std::unordered_map<Key, Value, std::hash<Key>, std::equal_to<Key>, RealMallocAllocator<std::pair<const Key, Value>>>;

  template<typename Value>
  using RealMallocSet = std::unordered_set<Value, std::hash<Value>, std::equal_to<Value>, RealMallocAllocator<Value>>;


  class Manager {
  public:
    Manager();
    ~Manager();

    void* begin_trace(void *id, void *ret_addr);
    void* end_trace(void *id, void *ret_addr);
    void* jump_to_trace(void *id);

    void* backwards_branch(void *id, void *ret_addr, void **stack_ptr);
    void* fellthrough_branch(void *id, void *ret_addr, void **stack_ptr);

    // void ensure_not_traced();

    void *temp_disable(void *ret_addr);
    void *temp_enable(void *ret_addr);

    void *begin_merge_block();
    void *end_merge_block();

    void disable_branch(void *id);

    void* is_traced_call();

    void do_not_trace_method(void *addr);

    void* ensure_not_traced();

    void* end_branchable_frame(void *ret_addr, void **stack_ptr);

    uint32_t get_thread_id();

    tracer_stack_state* push_tracer_stack();
    tracer_stack_state pop_tracer_stack();
    uint32_t tracer_stack_size();
    tracer_stack_state* get_tracer_head();

    void print_info();

  private:
    bool should_trace_method(void *ptr);

  public:
    struct branch_info {
      int count = 0;
      int count_fellthrough = 0;
      Tracer *tracer = nullptr;
      void *starting_point = nullptr;
      bool disabled = false;
      int64_t traced_instruction_count = 0;
      int64_t longest_trace_instruction_count = 0;
      int sub_branches = 0;
      int finish_traces = 0; // number of branched traces that reached the end (not merged blocked back)
      uint64_t *trace_loop_counter = nullptr;

#ifdef CONF_USE_TIMERS
      timespec first_observed_time = {0,0};
#endif

#ifdef CONF_ESTIMATE_INSTRUCTIONS
      // this may be wrong since it can be impacted by time that the processor has switched
      // or the task has been interruptted
      // TODO: maybe in the future use the amount of thread cpu time to estimate this
      uint64_t avg_observed_instructions = 0;
#endif
    };

    // std::unordered_map<
    //   void*,
    //   branch_info,
    //   // should be the same as normal
    //   std::hash<void*>,
    //   std::equal_to<void*>,
    //   RealMallocAllocator<std::pair<const void*, branch_info>>
    //   >
    RealMallocMap<void*, branch_info> branches;

    struct merge_location_info {
      RealMallocSet<mem_loc_t> rips;
#ifdef CONF_MERGE_BACK_ON_RET
      bool is_method_return = false;
#endif

    };

#ifdef CONF_CHECK_MERGE_RIP
    // std::unordered_map<
    //   mem_loc_t,
    //   mem_loc_t,
    //   std::hash<mem_loc_t>,
    //   std::equal_to<mem_loc_t>,
    //   RealMallocAllocator<std::pair<const mem_loc_t, mem_loc_t>>
    //   >
    RealMallocMap<mem_loc_t, RealMallocSet<mem_loc_t> > merge_rip;
#endif
  private:
    // std::unordered_set<
    //   void*,
    //   std::hash<void*>,
    //   std::equal_to<void*>,
    //   RealMallocAllocator<void*>
    //   >
    RealMallocSet<void*> no_trace_methods;

    std::atomic<uint32_t> thread_id_counter;

    // tbb::concurrent_unordered_map<uint64_t, branch_info> branches;
    // tbb::concurrent_unordered_set<uint64_t> no_trace_methods;

#ifdef CONF_USE_TIMERS
#define TRACE_SPEED_LIMIT(time, cnt)              \
    timespec speed_limit_time ## time = {0, 0} ;  \
    long speed_limit_last_icount ## time = 0;

    CONF_TRACE_INSTRUCTION_LIMIT_PER_TIME(TRACE_SPEED_LIMIT);
#undef TRACE_SPEED_LIMIT
#endif

    friend class Tracer;
  };

  // if we have nested tracers eg an outer loop calls an inner loop
  // or if we have an outter tracer disabled and an inner tracer running still
  struct tracer_stack_state {
    Tracer *tracer = nullptr;
    void *resume_addr = nullptr;
    void *trace_id = nullptr;
    bool is_temp_disabled = false;
    bool is_traced = false;
    bool is_compiled = false;

    // when this frame is poped if it should use the return address in the frame above it
    // essentially if this frame was created from a tracer
    bool return_to_trace_when_done = false;

    int32_t frame_id = -1;

    mem_loc_t frame_stack_ptr = -1;

#ifdef CONF_ESTIMATE_INSTRUCTIONS
    int num_backwards_loops = 0;
    uint64_t instruction_cnt_at_start = 0;
    uint64_t sub_frame_num_instructions = 0;
#endif

    //void *d_ret = nullptr;
    //bool did_abort = false;
  };

  struct tracer_method_stack_s {
    mem_loc_t method_address;
    mem_loc_t return_stack_pointer;

#ifdef CONF_MERGE_BACK_ON_RET
    int corresponding_merge_block = 0;
#endif

    tracer_method_stack_s(mem_loc_t a=0, mem_loc_t b=0):
      method_address(a), return_stack_pointer(b) {}
  };

  struct tracer_merge_block_stack_s {
    mem_loc_t merge_head = 0; // head of linked list for this merge point

#ifdef CONF_MERGE_BACK_ON_RET
    bool method_merge = false;
#endif

    tracer_merge_block_stack_s() {}
  };

  //extern thread_local std::vector<tracer_stack_state> trace_return_addr;
  //extern thread_local Tracer *tracer; // current running tracer
  //extern thread_local void *trace_id; // id of current executing trace
  //extern thread_local bool is_traced;
  extern Manager *manager;
  extern thread_local bool protected_malloc;
  extern std::atomic<Tracer*> free_tracer_list;
  extern thread_local int32_t branchable_frame_id;


  class CodeBuffer final {
  public:
    //
  public:
    // creates a Code Buffer that "owns" a region of memory that is of at least size
    static CodeBuffer* CreateBuffer(size_t size);
    // when done with a code buffer release it back to a memory pool
    static void Release(CodeBuffer *x);

    //CodeBuffer(size_t size);
    CodeBuffer(mem_loc_t start, size_t size, bool override_can_write=false);
    CodeBuffer();

    CodeBuffer(CodeBuffer &&x);

    ~CodeBuffer();

    CodeBuffer& operator=(CodeBuffer &&x);

    //void *getBuffer() { return buffer; }
    const inline size_t getSize() { return size - trampolines_size + external_trampolines_size; }
    const inline size_t getFree() { return size - trampolines_size - buffer_consumed; }

    inline uint8_t* whereByte(mem_loc_t offset) const {
      assert(offset < size - trampolines_size + external_trampolines_size);
      if(offset < size - trampolines_size) {
        return buffer + offset;
      } else if(offset - size + trampolines_size < external_trampolines_size) {
        return external_trampolines + offset - size + trampolines_size;
      }
      assert(0);
    }

    inline uint8_t readByte(mem_loc_t offset) const {
      return *whereByte(offset);
    }
    inline void writeByte(mem_loc_t offset, uint8_t val) {
      assert(offset < size);
      assert(can_write_buffer);
      *whereByte(offset) = val;
    }

  public:
    // write another code buffer to the end of this one
    CodeBuffer writeToEnd(const CodeBuffer &other, long start=-1, long end=-1);

    // write to the bottom, reverse order so used for small trampolines
    CodeBuffer writeToBottom(const CodeBuffer &other, long start=-1, long end=-1);

    void print();

    inline size_t getOffset() const { return buffer_consumed; }
    inline void setOffset(size_t o) { buffer_consumed = o; }
    inline mem_loc_t getRawBuffer() { return (mem_loc_t)buffer; }

    inline void __set_can_write() { can_write_buffer = true; }

  public:
    template<typename SizeT> void replace_stump(SizeT from, SizeT to) {
#ifndef NDEBUG
      uint8_t did_replace = 0;
#endif
      SizeT current_value = 0;
      size_t location = 0;
      while(location < buffer_consumed) {
        current_value <<= 8;
        current_value |= readByte(location);
        if(current_value == from) {
          for(int i = sizeof(SizeT) - 1; i >= 0; i--) {
            writeByte(location - i, to >> 8 * (sizeof(SizeT) - i - 1));
          }
#ifndef NDEBUG
          did_replace++;
#else
          break;
#endif
        }
        location++;
      }
      assert(did_replace == 1);
    }

    template<typename SizeT> SizeT* find_stump(SizeT from) {
      SizeT *ret = nullptr;
#ifndef NDEBUG
      uint8_t did_find = 0;
#endif
      SizeT current_value = 0;
      size_t location = 0;
      while(location < buffer_consumed) {
        current_value <<= 8;
        current_value |= readByte(location);
        if(current_value == from) {
          ret = (SizeT*)whereByte(location - sizeof(SizeT) + 1);
#ifndef NDEBUG
          did_find++;
#else
          break;
#endif
        }
        location++;
      }
      assert(did_find == 1);
      assert(*ret == from);
      return ret;
    }

  public:
    // std::mutex generation_mutex;
    // // std::unique_lock<std::mutex> generation_lock = std::unique_lock<std::mutex>(_generation_mutex);

    // CodeBuffer *_next;

  private:
    uint8_t *buffer;
    size_t trampolines_size = 0;  // trampolines on the end of this buffer
    size_t size;
    size_t buffer_consumed;
    bool owns_buffer;
    bool can_write_buffer;

    uint8_t *external_trampolines = nullptr;
    size_t external_trampolines_size = 0;

    friend class SimpleCompiler;

  };


  template <typename T> inline int bits_set(T x) {
    return __builtin_popcount(x);
  }


  template<typename ...T>
  inline void red_printf(const T &... args) {
    // we have to avoid calls that could possibly use malloc or other systems which are maintaining some internal state
    // so this is using a existing fixed size buffer and syscalls directly to avoid potential buffering/shared state outside of redmagic
    char buffer[200];
    int b = snprintf(buffer, sizeof(buffer), args...);
    ::write(2, buffer, b);
  }

#ifdef CONF_ESTIMATE_INSTRUCTIONS
  // assembly code to read the TSC
  static inline uint64_t RDTSC() {
    unsigned int hi, lo;
    __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
    return (((uint64_t)hi) << 32) | lo;
  }

  extern thread_local uint64_t last_thread_instructions;
  extern thread_local uint64_t num_instructions_add;

  static inline uint64_t instruction_cnt() {
    // this value can go down when the processor resets or it changes between cores
    uint64_t i = RDTSC();
    if(i < last_thread_instructions)
      num_instructions_add += last_thread_instructions - i;
    last_thread_instructions = i;
    return i + num_instructions_add;
  }
#endif

#ifdef CONF_USE_TIMERS
  static inline timespec time_delta(timespec start, timespec end) {
    timespec temp;
    if ((end.tv_nsec-start.tv_nsec)<0) {
      temp.tv_sec = end.tv_sec-start.tv_sec-1;
      temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    } else {
      temp.tv_sec = end.tv_sec-start.tv_sec;
      temp.tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return temp;
  }

  static inline uint64_t time_ms(timespec t) {
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
  }

#endif
}



#endif // REDMAGIC_INTERNAL_H_
