#include "compiler.h"

#include <sys/mman.h>

using namespace redmagic;

extern "C" void red_asm_compile_buff_near();

CodeBuffer::CodeBuffer(size_t size):
  size(size),
  owns_buffer(true),
  can_write_buffer(true),
  buffer_consumed(0)
{
  buffer = (uint8_t*)mmap((void*)&red_asm_compile_buff_near, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

  if(buffer == MAP_FAILED) {
    perror("failed to mmap buffer");
  }
  memset(buffer, 0, size);
  init();
}

CodeBuffer::~CodeBuffer() {
  if(owns_buffer) {
    if(munmap(buffer, size) < 0) {
      perror("failed to unmap buffer");
    }
  }
}

CodeBuffer::CodeBuffer(mem_loc_t start, size_t size):
  buffer((uint8_t*)start),
  size(size),
  owns_buffer(false),
  can_write_buffer(false),
  buffer_consumed(size)
{
  init();
}

#ifdef CONF_COMPILE_IN_PARENT
CodeBuffer::CodeBuffer(Tracer *tracer, mem_loc_t start, size_t size):
  buffer((uint8_t*)start),
  size(size),
  owns_buffer(false),
  can_write_buffer(false),
  buffer_consumed(size)
{
  _tracer = tracer;
  init();
}
#endif

#ifdef CONF_COMPILE_IN_PARENT
uint8_t CodeBuffer::readByte(mem_loc_t offset) {
  assert(offset < size);
  if(_tracer) {
    assert(!buffer);
    return _tracer->readByte(offset + (mem_loc_t)buffer);
  } else {
    return buffer[offset];
  }
}
void CodeBuffer::writeByte(mem_loc_t offset, uint8_t val) {
  assert(offset < size);
  assert(can_write_buffer);
  if(_tracer) {
    _tracer->writeByte(offset + (mem_loc_t)buffer, val);
  } else {
    buffer[offset] = val;
  }
}
#endif


int CodeBuffer::udis_input_hook(ud_t *ud) {
  CodeBuffer *cb = (CodeBuffer*)ud_get_user_opaque_data(ud);
  return cb->readByte(cb->ud_offset++);
}

void CodeBuffer::init() {
  ud_init(&disassm);
  ud_set_user_opaque_data(&disassm, this);
  ud_set_input_hook(&disassm, CodeBuffer::udis_input_hook);
  ud_set_mode(&disassm, 64);
  ud_set_vendor(&disassm, UD_VENDOR_INTEL);
  ud_set_syntax(&disassm, UD_SYN_INTEL);
}

void CodeBuffer::writeToEnd(CodeBuffer &other, long start, long end) {
  mem_loc_t position = 0;
  //mem_loc_t self_offset = buffer_consumed;

  if(start > 0)
    position = start;
  mem_loc_t startl = position;
  mem_loc_t self_start = buffer_consumed;
  assert(end < 0 || end < other.buffer_consumed);
  mem_loc_t endl = end;
  if(end < 0) {
    endl = other.buffer_consumed;
  }

  assert(endl <= other.buffer_consumed);
  assert(endl - position + buffer_consumed < size);

  while(position < endl) {
    writeByte(buffer_consumed++, other.readByte(position++));
  }
  for(auto j : other.jumps) {
    if(j.buffer_offset >= startl && j.buffer_offset < endl) {
      struct rebind_jumps new_jmp = j;
      new_jmp.buffer_offset = j.buffer_offset - startl + self_start;
      jumps.push_back(new_jmp);
    }
  }
}
