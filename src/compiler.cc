#include "compiler.h"

using namespace redmagic;

Compiler::Compiler(
#ifdef CONF_COMPILE_IN_PARENT
                   Tracer *tracer
#else
                   std::vector<JumpTrace> &&traces
#endif
                   ) {
#ifdef CONF_COMPILE_IN_PARENT
  _tracer = tracer;
  traces = std::move(_tracer->traces);
#else
  this->traces = std::move(traces);
#endif
}

unsigned char Compiler::readByte(mem_loc_t where) {
#ifdef CONF_COMPILE_IN_PARENT
  return _tracer->readByte(where);
#else
  // then we are in the same process as where we want to read from, so we can directly read
  return *(unsigned char*)where;
#endif
}


namespace redmagic {
  size_t relocate_code(ud_t *source, void *dest, size_t length, size_t output_limit) {
    size_t dest_len = 0;
    size_t processed_len = 0;
    while(processed_len < length && dest_len < output_limit) {
      processed_len += ud_disassemble(source);

      switch(ud_insn_mnemonic(source)) {

      }
    }

    return dest_len;

  }
}
