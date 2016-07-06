#ifndef REDMAGIC_COMPILER_H_
#define REDMAGIC_COMPILER_H_


#include "jit_internal.h"

namespace redmagic {

#if 0
  class Compiler {

  public:
    Compiler(
#ifdef CONF_COMPILE_IN_PARENT
             Tracer *tracer
#else
             std::vector<JumpTrace> &&traces
#endif
             );

    void Run();

  private:
    unsigned char readByte(mem_loc_t where);

  private:
#ifdef CONF_COMPILE_IN_PARENT
    Tracer *_tracer;
#endif
    std::vector<JumpTrace> traces;

  };
#endif


  // output buffer for the compiler
  class CodeBuffer final {
  public:
    CodeBuffer(size_t size);
#ifdef CONF_COMPILE_IN_PARENT
    CodeBuffer(Tracer *tracer, mem_loc_t start, size_t size);
#endif
    CodeBuffer(mem_loc_t start, size_t size);

    ~CodeBuffer();

    //void *getBuffer() { return buffer; }
    size_t getSize() { return size; }

#ifdef CONF_COMPILE_IN_PARENT
    uint8_t readByte(mem_loc_t offset);
    void writeByte(mem_loc_t offset, uint8_t val);
#else
    inline uint8_t readByte(mem_loc_t offset) {
      assert(offset < size);
      return buffer[offset];
    }
    inline void writeByte(mem_loc_t offset, uint8_t val) {
      assert(offset < size);
      assert(can_write_buffer);
      buffer[offset] = val;
    }
#endif

  public:
    // write another code buffer to the end of this one
    void writeToEnd(CodeBuffer &other, long start=-1, long end=-1);
    void print();

    inline size_t getOffset() { return buffer_consumed; }

  public:
    ud_t disassm;
  private:
    static int udis_input_hook(ud_t *ud);
    mem_loc_t ud_offset;
    void init();
    void processJumps();

  private:
    uint8_t *buffer;
    size_t size;
    size_t buffer_consumed;
    bool owns_buffer;
    bool can_write_buffer;
#ifdef CONF_COMPILE_IN_PARENT
    Tracer *_tracer;
#endif
    struct rebind_jumps {
      mem_loc_t buffer_offset;
      // suppose that this could disappear so might not be best idea to deallcate these and reallocate?
      CodeBuffer *origional_buffer;
      mem_loc_t origional_offset;
    };
    std::vector<rebind_jumps> jumps;

  };


  inline int bits_set(unsigned int x) {
    return __builtin_popcount(x);
  }

  std::vector<mem_loc_t> find_jumps(ud_t *disassm, size_t size);

}

#endif // REDMAGIC_COMPILER_H_
