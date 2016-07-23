#include "jit_internal.h"

#include <sys/mman.h>
#include <mutex>



using namespace redmagic;

extern "C" void red_asm_compile_buff_near();

namespace redmagic {
  std::mutex code_buffer_mutex;

  std::vector<CodeBuffer*> owning_code_buffers;

  std::vector<CodeBuffer*> unallocated_code_buffers;
}

CodeBuffer* CodeBuffer::CreateBuffer(size_t size) {
  std::lock_guard<std::mutex> lock(code_buffer_mutex);

  for(auto it = unallocated_code_buffers.begin(); it != unallocated_code_buffers.end(); it++) {
    if((*it)->getFree() > size) {
      CodeBuffer *ret = *it;
      unallocated_code_buffers.erase(it);
      return ret;
    }
  }

  // we could not find an open buffer that has enough space to satasify this request
  if(size < 4 * 1024 * 1024) {
    // the min size that we will allocate
    size = 4 * 1024 * 1024;
  } else if((size & (4*1024 - 1)) != 0) {
    // request in page amounts
    size += 4 * 1024;
    size &= (4*1024 - 1);
  }

  uint8_t *buffer = (uint8_t*)mmap((void*)&red_asm_compile_buff_near,
    size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

  if(buffer == MAP_FAILED) {
    perror("failed to mmap buffer");
  }
  memset(buffer, 0, size);

  CodeBuffer* ret = new CodeBuffer();
  owning_code_buffers.push_back(ret);

  ret->size = size;
  ret->owns_buffer = true;
  ret->can_write_buffer = true;
  ret->buffer_consumed = 0;
  ret->buffer = buffer;

  return ret;
}


void CodeBuffer::Release(CodeBuffer *x) {
  std::lock_guard<std::mutex> lock(code_buffer_mutex);

  assert(x->owns_buffer);

  // this buffer should not already be in the list of currently unused
  for(auto it : unallocated_code_buffers) {
    assert(x != it);
  }

  unallocated_code_buffers.push_back(x);
}

// CodeBuffer::CodeBuffer(size_t size):
//   size(size),
//   owns_buffer(true),
//   can_write_buffer(true),
//   buffer_consumed(0)
// {

//   buffer = (uint8_t*)mmap((void*)&red_asm_compile_buff_near,
//     size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);

//   if(buffer == MAP_FAILED) {
//     perror("failed to mmap buffer");
//   }
//   memset(buffer, 0, size);
// }

CodeBuffer::~CodeBuffer() {
  // if(owns_buffer) {
  //   if(munmap(buffer, size) < 0) {
  //     perror("failed to unmap buffer");
  //   }
  // }
  // can't un allocate an owning buffer atm
  assert(!owns_buffer);
}

CodeBuffer::CodeBuffer(mem_loc_t start, size_t size, bool override_can_write):
  buffer((uint8_t*)start),
  size(size),
  owns_buffer(false),
  can_write_buffer(override_can_write),
  buffer_consumed(size)
{
}

CodeBuffer::CodeBuffer():
  buffer(nullptr),
  size(0),
  owns_buffer(false),
  can_write_buffer(false),
  buffer_consumed(0)
{}

CodeBuffer::CodeBuffer(CodeBuffer &&x) {
  buffer = x.buffer;
  trampolines_size = x.trampolines_size;
  size = x.size;
  buffer_consumed = x.buffer_consumed;
  assert(!x.owns_buffer); /////// TODO: move an owning buffer?
  owns_buffer = x.owns_buffer;
  x.owns_buffer = false;
  can_write_buffer = x.can_write_buffer;
  external_trampolines = x.external_trampolines;
  external_trampolines_size = x.external_trampolines_size;
}

CodeBuffer CodeBuffer::writeToEnd(const CodeBuffer &other, long start, long end) {
  assert(other.external_trampolines == nullptr); // we can't relocate this without understanding the code
  mem_loc_t position = 0;
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

  CodeBuffer ret((mem_loc_t)buffer + self_start, buffer_consumed - self_start);
  ret.can_write_buffer = true;
  return ret;
}

CodeBuffer CodeBuffer::writeToBottom(const CodeBuffer &other, long start, long end) {
  assert(other.external_trampolines == nullptr); // we can't relocate this without understanding the code
  assert(external_trampolines == nullptr || (external_trampolines >= buffer && external_trampolines <= buffer + size));
  mem_loc_t position = 0;
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

  size_t gsize = startl - endl;
  size_t target_position = size - trampolines_size - gsize;
  trampolines_size += gsize;

  while(position < endl) {
    writeByte(target_position++, other.readByte(position++));
  }

  CodeBuffer ret((mem_loc_t)buffer + self_start, buffer_consumed - self_start);
  ret.can_write_buffer = true;
  return ret;

}

static int codebuff_input_hook(ud_t *ud) {
  uint8_t **buff_location = (uint8_t**)ud_get_user_opaque_data(ud);

  uint8_t r = **buff_location;
  *buff_location++;
  return r;
}


void CodeBuffer::print() {
  ud_t disassm;
  uint8_t *buff_location = buffer;
  ud_init(&disassm);
  ud_set_user_opaque_data(&disassm, &buff_location);
  ud_set_input_hook(&disassm, &codebuff_input_hook);
  ud_set_mode(&disassm, 64);
  ud_set_vendor(&disassm, UD_VENDOR_INTEL);
  ud_set_syntax(&disassm, UD_SYN_INTEL);
  ud_set_pc(&disassm, (mem_loc_t)buffer);

  int icount = 0;

  while(ud_disassemble(&disassm)) {
    printf("%8i\t%-35s [%#016lx] %s\n", ++icount, ud_insn_asm(&disassm), ud_insn_off(&disassm), ud_insn_hex(&disassm));

    if(buff_location - buffer >= size)
      break;
  }
  fflush(stdout);
}
