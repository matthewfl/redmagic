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

// for write syscall
#include <unistd.h>

#include <udis86.h>

namespace redmagic {

  class Manager;
  class CodeBuffer;
  class Tracer;
  class SimpleCompiler;

  typedef decltype(((struct user_regs_struct*)(NULL))->r15) register_t;
  typedef uint64_t mem_loc_t; // a memory location in the debugged program

  struct tracer_stack_state;

  class Manager {
  public:
    Manager();

    void* begin_trace(void *id, void *ret_addr);
    void* end_trace(void *id, void *ret_addr);
    void* jump_to_trace(void *id);

    void* backwards_branch(void *id, void *ret_addr);
    void* fellthrough_branch(void *id, void *ret_addr);

    void ensure_not_traced();

    void *temp_disable(void *resume_pc);
    void *temp_enable(void *resume_pc);

    void disable_branch(void *id);

    void* is_traced_call();

    void do_not_trace_method(void *addr);



    uint32_t get_thread_id();

    tracer_stack_state* push_tracer_stack();
    tracer_stack_state pop_tracer_stack();
    uint32_t tracer_stack_size();
    tracer_stack_state* get_tracer_head();

  private:
    bool should_trace_method(void *ptr);

  public:
    struct branch_info {
      int count = 0;
      Tracer *tracer = nullptr;
      void *starting_point = nullptr;
      bool disabled = false;
    };

    std::unordered_map<void*, branch_info> branches;
  private:
    std::unordered_set<void*> no_trace_methods;

    std::atomic<uint32_t> thread_id_counter;

    // tbb::concurrent_unordered_map<uint64_t, branch_info> branches;
    // tbb::concurrent_unordered_set<uint64_t> no_trace_methods;

    friend class Tracer;
  };

  // if we have nested tracers eg an outer loop calls an inner loop
  // or if we have an outter tracer disabled and an inner tracer running still
  //
  struct tracer_stack_state {
    Tracer *tracer = nullptr;
    void *resume_addr = nullptr;
    void *trace_id = nullptr;
    bool is_temp_disabled = false;
    bool is_traced = false;
    bool is_compiled = false;
    bool did_abort = false;
  };

  //extern thread_local std::vector<tracer_stack_state> trace_return_addr;
  //extern thread_local Tracer *tracer; // current running tracer
  //extern thread_local void *trace_id; // id of current executing trace
  //extern thread_local bool is_traced;
  extern Manager *manager;
  extern thread_local bool protected_malloc;


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
    // struct rebind_jumps {
    //   mem_loc_t buffer_offset;
    //   // suppose that this could disappear so might not be best idea to deallcate these and reallocate?
    //   CodeBuffer *origional_buffer;
    //   mem_loc_t origional_offset;
    // };
    // std::vector<rebind_jumps> jumps;

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


}



#endif // REDMAGIC_INTERNAL_H_
