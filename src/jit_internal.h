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
#include <map>
#include <vector>
#include <set>

#include <errno.h>

#include <boost/context/all.hpp>
#include <memory>


#include "udis86.h"

namespace redmagic {

  class Manager;
  class CodeBuffer;
  class Tracer;

  typedef decltype(((struct user_regs_struct*)(NULL))->r15) register_t;
  typedef uint64_t mem_loc_t; // a memory location in the debugged program


  class Manager {
  public:
    Manager();

    void begin_trace(void *id);
    void end_trace(void *id);
    void jump_to_trace(void *id);

    void backwards_branch(void*);
    void fellthrough_branch(void*);

    void ensure_not_traced();

  private:
    bool should_trace_method(void *ptr);

  private:
    std::map<void*, int> branch_count;
    std::map<void*, Tracer*> trace;
    std::set<void*> no_trace_methods;


    friend class Tracer;
  };

  class CodeBuffer final {
  public:
    CodeBuffer(size_t size);
    CodeBuffer(mem_loc_t start, size_t size);
    CodeBuffer();

    ~CodeBuffer();

    //void *getBuffer() { return buffer; }
    size_t getSize() { return size; }

    inline uint8_t readByte(mem_loc_t offset) {
      assert(offset < size);
      return buffer[offset];
    }
    inline void writeByte(mem_loc_t offset, uint8_t val) {
      assert(offset < size);
      assert(can_write_buffer);
      buffer[offset] = val;
    }

  public:
    // write another code buffer to the end of this one
    CodeBuffer writeToEnd(CodeBuffer &other, long start=-1, long end=-1);
    void print();

    inline size_t getOffset() { return buffer_consumed; }
    inline void setOffset(size_t o) { buffer_consumed = o; }
    inline mem_loc_t getRawBuffer() { return (mem_loc_t)buffer; }

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

  private:
    uint8_t *buffer;
    size_t size;
    size_t buffer_consumed;
    bool owns_buffer;
    bool can_write_buffer;
    // struct rebind_jumps {
    //   mem_loc_t buffer_offset;
    //   // suppose that this could disappear so might not be best idea to deallcate these and reallocate?
    //   CodeBuffer *origional_buffer;
    //   mem_loc_t origional_offset;
    // };
    // std::vector<rebind_jumps> jumps;

  };


  inline int bits_set(unsigned int x) {
    return __builtin_popcount(x);
  }



}



#endif // REDMAGIC_INTERNAL_H_
