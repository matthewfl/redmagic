#include "compiler.h"

#include <sys/mman.h>

using namespace redmagic;

extern "C" void red_asm_compile_buff_near();

CompileBuffer::CompileBuffer(size_t size): size(size) {
  buffer = (char*)mmap((void*)&red_asm_compile_buff_near, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

  if(buffer == MAP_FAILED) {
    perror("failed to mmap buffer");
  }
}

CompileBuffer::~CompileBuffer() {
  if(munmap(buffer, size) < 0) {
    perror("failed to unmap buffer");
  }
}
