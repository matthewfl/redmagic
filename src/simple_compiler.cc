#include "simple_compiler.h"

using namespace redmagic;
using namespace asmjit;

SimpleCompiler::~SimpleCompiler() {
  if(buffer) {
    finalize();
  }
}

CodeBuffer SimpleCompiler::finalize() {
  assert(buffer);
  // check that no one else used this buffer while this was running
  assert(buffer->getRawBuffer() + buffer->getOffset() == buffer_cursor);
  restore_registers();
  void *start = make();
  assert(start == (void*)buffer_cursor);
  size_t len = getOffset();
  buffer->setOffset(buffer->getOffset() + len);

  CodeBuffer ret(buffer_cursor, len);
  ret.can_write_buffer = true;
  if(trampolines_used) {
    ret.external_trampolines_size = trampolines_used;
    ret.external_trampolines = buffer->buffer + buffer->size - buffer->trampolines_size;
  }
  buffer = NULL;
  return ret;
}

void SimpleCompiler::restore_registers() {
  uint64_t restore = clobbered_registers;
  int indx = 0;
  while(restore) {
    if(restore & 0x1) {
      mov(get_asm_register_from_sys(indx), x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + indx * 8 + move_stack_by));
    }
    restore >>= 1;
    indx++;
  }
  clobbered_registers = 0;
}

void SimpleCompiler::protect_register(int id) {
  if((clobbered_registers & (1 << id)) == 0) {
    mov(x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + id * 8 + move_stack_by), get_asm_register_from_sys(id));
    clobbered_registers |= 1 << id;
  }
}

const asmjit::X86GpReg& SimpleCompiler::get_scratch_register() {
  int indx = 0;
  if(~regs_using & clobbered_registers) {
    // if there is a clobbered register that we can use as scratch then favor that
    while(indx <= RDI) {
      if((~regs_using & clobbered_registers & (1 << indx)) == 0) {
        regs_using |= 1 << indx;
        return get_register(indx);
      }
    }
  }
  while(indx <= RDI) {
    if((regs_using & (1 << indx)) == 0) {
      protect_register(indx);
      regs_using |= 1 << indx;
      return get_asm_register_from_sys(indx);
    }
  }
  // did not find a register
  assert(0);
}

const asmjit::X86GpReg& SimpleCompiler::get_register(int id) {
  assert((clobbered_registers & (1 << id)) == 0);
  regs_using |= 1 << id;
  return get_asm_register_from_sys(id);
}

void SimpleCompiler::add_used_registers(uint64_t regs) {
  assert((clobbered_registers & regs) == 0);
  regs_using |= regs;
}

void SimpleCompiler::set_label_address(const asmjit::Label &label, mem_loc_t addr) {
  auto offset = getOffset();
  setCursor((uint8_t*)addr);
  bind(label);
  setOffset(offset);
}


void SimpleCompiler::MemToRegister(mem_loc_t mem, int reg) {
  auto r = get_register(reg);
  mov(r, imm_u(mem));
  mov(r, x86::ptr(r));
}

void SimpleCompiler::RegisterToMem(int reg, mem_loc_t mem) {
  auto r = get_register(reg);
  auto scr = get_scratch_register();
  mov(scr, imm_u(mem));
  mov(x86::ptr(scr), r);
}

void SimpleCompiler::SetRegister(int reg, register_t val) {
  mov(get_register(reg), imm_u(val));
}

void SimpleCompiler::TestRegister(int reg, register_t val) {
  auto r = get_register(reg);
  Label success = newLabel();
  Label failure = newLabel();
  pushf();
  test(r, imm_u(val));
  je(success);
  // TODO: make this use some label for a generated address
  popf();
  //jmp(imm_u(0xfafafafafafafafa));
  jmp(failure);
  bind(success);
  popf();
}

void SimpleCompiler::TestMemoryLocation(mem_loc_t where, register_t val) {
  Label success = newLabel();
  Label failure = newLabel();
  auto scr = get_scratch_register();
  mov(scr, imm_ptr(where));
  pushf();
  test(x86::word_ptr(scr), imm_u(val));
  je(success);
  popf();
  jmp(failure); // TODO: bind this label
  bind(success);
  popf();
}

uint64_t* SimpleCompiler::MakeCounter() {
  uint64_t *cptr = (uint64_t*)(buffer->buffer + buffer->size - buffer->trampolines_size - sizeof(uint64_t));
  *cptr = 0;
  buffer->trampolines_size += sizeof(uint64_t);
  auto label = newLabel();
  set_label_address(label, (mem_loc_t)cptr);
  auto scr = get_scratch_register();
  //auto scr2 = get_scratch_register();
  //mov(scr2, imm_ptr(cptr));
  // mov(scr, x86::ptr(label));
  // inc(scr);
  // mov(x86::ptr(label), scr);

  // TODO: make this add to this location
  add(x86::ptr(x86::rip, 10), 1);
  assert(0);

  return cptr;
}

void SimpleCompiler::PushMemoryLocationValue(mem_loc_t where) {
  auto scr = get_scratch_register();
  mov(scr, imm_u(where));
  // // TODO: bug in asmjit prevents push from working directly with pointers???
  // mov(scr, x86::ptr(scr));
  push(x86::word_ptr(scr));
  move_stack_by -= sizeof(register_t);
}


mem_loc_t SimpleCompiler::MakeResumeTraceBlock(mem_loc_t tracer_base_ptr, mem_loc_t resume_pc) {
  SimpleCompiler resume_block(buffer);
  assert(0);
}




/////////////////////////////////////////////////////////////////////////
// largely copied from asmjit/x86/x86assembler.cpp
////////////////////////////////////////////////////////////////////////

//! Encode ModR/M.
static ASMJIT_INLINE uint32_t x86EncodeMod(uint32_t m, uint32_t o, uint32_t rm) {
  assert(m <= 3);
  assert(o <= 7);
  assert(rm <= 7);
  return (m << 6) + (o << 3) + rm;
}

size_t SimpleCompiler::_relocCode(void* _dst, asmjit::Ptr baseAddress) const noexcept {
  uint32_t arch = getArch();
  uint8_t* dst = static_cast<uint8_t*>(_dst);
  assert(_dst == (void*)buffer_cursor);

#if !defined(ASMJIT_DISABLE_LOGGER)
  Logger* logger = getLogger();
#endif // ASMJIT_DISABLE_LOGGER

  size_t minCodeSize = getOffset();   // Current offset is the minimum code size.
  size_t maxCodeSize = getCodeSize(); // Includes all possible trampolines.

  // We will copy the exact size of the generated code. Extra code for trampolines
  // is generated on-the-fly by the relocator (this code doesn't exist at the moment).
  ::memcpy(dst, _buffer, minCodeSize);

  // Trampoline pointer.
  uint8_t* tramp = (uint8_t*)(buffer->buffer + buffer->size - buffer->trampolines_size - 8); //dst + minCodeSize;
  //uint8_t* dst_end = dst + minCodeSize;

  // Relocate all recorded locations.
  size_t relocCount = _relocations.getLength();
  const RelocData* rdList = _relocations.getData();

  for (size_t i = 0; i < relocCount; i++) {
    const RelocData& rd = rdList[i];

    // Make sure that the `RelocData` is correct.
    Ptr ptr = rd.data;

    size_t offset = static_cast<size_t>(rd.from);
    ASMJIT_ASSERT(offset + rd.size <= static_cast<Ptr>(maxCodeSize));

    // Whether to use trampoline, can be only used if relocation type is
    // kRelocAbsToRel on 64-bit.
    bool useTrampoline = false;

    switch (rd.type) {
      case kRelocAbsToAbs:
        break;

      case kRelocRelToAbs:
        ptr += baseAddress;
        break;

      case kRelocAbsToRel:
        ptr -= baseAddress + rd.from + 4;
        break;

     case kRelocTrampoline:
        ptr -= baseAddress + rd.from + 4;
        if (!Utils::isInt32(static_cast<SignedPtr>(ptr))) {
          ptr = (Ptr)tramp - (baseAddress + rd.from + 4);
          useTrampoline = true;
        }
        break;

      default:
        ASMJIT_NOT_REACHED();
    }

    switch (rd.size) {
      case 4:
        Utils::writeU32u(dst + offset, static_cast<int32_t>(static_cast<SignedPtr>(ptr)));
        break;

      case 8:
        Utils::writeI64u(dst + offset, static_cast<int64_t>(ptr));
        break;

      default:
        ASMJIT_NOT_REACHED();
    }

    // Handle the trampoline case.
    if (useTrampoline) {
      // Bytes that replace [REX, OPCODE] bytes.
      uint32_t byte0 = 0xFF;
      uint32_t byte1 = dst[offset - 1];

      // Call, patch to FF/2 (-> 0x15).
      if (byte1 == 0xE8)
        byte1 = x86EncodeMod(0, 2, 5);
      // Jmp, patch to FF/4 (-> 0x25).
      else if (byte1 == 0xE9)
        byte1 = x86EncodeMod(0, 4, 5);

      // Patch `jmp/call` instruction.
      ASMJIT_ASSERT(offset >= 2);
      dst[offset - 2] = byte0;
      dst[offset - 1] = byte1;

      // Absolute address.
      Utils::writeU64u(tramp, static_cast<uint64_t>(rd.data));

      // Advance trampoline pointer.
      tramp -= 8;
      buffer->trampolines_size += 8;
      // omfg, another reason why const is stupid
      const_cast<SimpleCompiler*>(this)->trampolines_used += 8;


#if !defined(ASMJIT_DISABLE_LOGGER)
      if (logger)
        logger->logFormat(Logger::kStyleComment, "; Trampoline %llX\n", rd.data);
#endif // !ASMJIT_DISABLE_LOGGER
    }
  }

  // if (arch == kArchX64)
  //   return (size_t)(dst_end - dst);
  // else
  return maxCodeSize;
}
