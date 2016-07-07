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


  template <typename T> inline int bits_set(T x) {
    return __builtin_popcount(x);
  }

  static int ud_register_to_size(ud_type t) {
    switch(t) {
    case UD_R_R15B:
    case UD_R_R14B:
    case UD_R_R13B:
    case UD_R_R12B:
    case UD_R_CH:
    case UD_R_BL:
    case UD_R_R11B:
    case UD_R_R10B:
    case UD_R_R9B:
    case UD_R_R8B:
    case UD_R_AL:
    case UD_R_CL:
    case UD_R_DL:
    case UD_R_DH:
    case UD_R_BH:
    case UD_R_AH:
      return 1;

    case UD_R_R15W:
    case UD_R_R14W:
    case UD_R_R13W:
    case UD_R_R12W:
    case UD_R_BP:
    case UD_R_BX:
    case UD_R_R11W:
    case UD_R_R10W:
    case UD_R_R9W:
    case UD_R_R8W:
    case UD_R_AX:
    case UD_R_CX:
    case UD_R_DX:
    case UD_R_SI:
    case UD_R_DI:
    case UD_R_SP:
      return 2;

    case UD_R_R15D:
    case UD_R_R14D:
    case UD_R_R13D:
    case UD_R_R12D:
    case UD_R_EBP:
    case UD_R_EBX:
    case UD_R_R11D:
    case UD_R_R10D:
    case UD_R_R9D:
    case UD_R_R8D:
    case UD_R_EAX:
    case UD_R_ECX:
    case UD_R_EDX:
    case UD_R_EDI:
    case UD_R_ESI:
    case UD_R_ESP:
    case UD_R_DS:
    case UD_R_ES:
    case UD_R_FS:
    case UD_R_GS:
    case UD_R_CS:
      return 4;

    case UD_R_R15:
    case UD_R_R14:
    case UD_R_R13:
    case UD_R_R12:
    case UD_R_RBP:
    case UD_R_RBX:
    case UD_R_R11:
    case UD_R_R10:
    case UD_R_R9:
    case UD_R_R8:
    case UD_R_RAX:
    case UD_R_RCX:
    case UD_R_RDX:
    case UD_R_RSI:
    case UD_R_RDI:
    case UD_R_RIP:
    case UD_R_RSP:
      return 8;

    default:
      return -1;

    }
  }

  // convert a register from udis to sys/reg.h
  static int ud_register_to_sys(ud_type t) {
    switch(t) {
    case UD_R_R15B:
    case UD_R_R15W:
    case UD_R_R15D:
    case UD_R_R15:
      return R15;
    case UD_R_R14B:
    case UD_R_R14W:
    case UD_R_R14D:
    case UD_R_R14:
      return R14;
    case UD_R_R13B:
    case UD_R_R13W:
    case UD_R_R13D:
    case UD_R_R13:
      return R13;
    case UD_R_R12B:
    case UD_R_R12W:
    case UD_R_R12D:
    case UD_R_R12:
      return R12;
    case UD_R_CH: // ??
    case UD_R_BP:
    case UD_R_EBP:
    case UD_R_RBP:
      return RBP;
    case UD_R_BL:
    case UD_R_BX:
    case UD_R_EBX:
    case UD_R_RBX:
      return RBX;
    case UD_R_R11B:
    case UD_R_R11W:
    case UD_R_R11D:
    case UD_R_R11:
      return R11;
    case UD_R_R10B:
    case UD_R_R10W:
    case UD_R_R10D:
    case UD_R_R10:
      return R10;
    case UD_R_R9B:
    case UD_R_R9W:
    case UD_R_R9D:
    case UD_R_R9:
      return R9;
    case UD_R_R8B:
    case UD_R_R8W:
    case UD_R_R8D:
    case UD_R_R8:
      return R8;
    case UD_R_AL:
    case UD_R_AX:
    case UD_R_EAX:
    case UD_R_RAX:
      return RAX;
    case UD_R_CL:
    case UD_R_CX:
    case UD_R_ECX:
    case UD_R_RCX:
      return RCX;
    case UD_R_DL:
    case UD_R_DX:
    case UD_R_EDX:
    case UD_R_RDX:
      return RDX;
    case UD_R_DH:
    case UD_R_SI:
    case UD_R_ESI:
    case UD_R_RSI:
      return RSI;
    case UD_R_BH:
    case UD_R_DI:
    case UD_R_EDI:
    case UD_R_RDI:
      return RDI;
      // orig rax
    case UD_R_RIP:
      // instrunction pointer??
      return RIP;
    case UD_R_CS:
      return CS;
      // eflags not directly accessable, use pushf and popf
    case UD_R_AH:
    case UD_R_SP:
    case UD_R_ESP:
    case UD_R_RSP:
      return RSP;
      // fsbase, gsbase
    case UD_R_DS:
      return DS;
    case UD_R_ES:
      return ES;
    case UD_R_FS:
      return FS;
    case UD_R_GS:
      return GS;
    default:
      return -1;
    }
  }



}



#endif // REDMAGIC_INTERNAL_H_
