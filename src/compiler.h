#ifndef REDMAGIC_COMPILER_H_
#define REDMAGIC_COMPILER_H_


#include "jit_internal.h"

namespace redmagic {

  class Compiler {

  public:
    Compiler(
#ifdef CONF_COMPILE_IN_PARENT
             Tracer *tracer
#else
             std::vector<JumpTrace> &&traces
#endif
             );

  private:
    unsigned char readByte(mem_loc_t where);

  private:
#ifdef CONF_COMPILE_IN_PARENT
    Tracer *_tracer;
#endif
    std::vector<JumpTrace> traces;

  };

  // output buffer for the compiler
  class CompileBuffer final {
  public:
    CompileBuffer(size_t size);
    ~CompileBuffer();

    void *getBuffer() { return buffer; }
    size_t getSize() { return size; }

  private:


  private:
    char *buffer;
    size_t size;
  };


}

#endif // REDMAGIC_COMPILER_H_
