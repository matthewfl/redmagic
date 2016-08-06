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

CodeBuffer SimpleCompiler::finalize_bottom() {
  assert(buffer);

  assert(buffer->getRawBuffer() + buffer->getOffset() == buffer_cursor);
  restore_registers();

  size_t size = getCodeSize();
  size_t minSize = getOffset();
  //setOffset(buffer->size - buffer->trampolines_size - size);
  //void *start = make();
  size_t old_trampolines_size = buffer->trampolines_size;
  void *gen_loc = buffer->buffer + buffer->size - buffer->trampolines_size - size;
  uint8_t *gen_tramp = buffer->buffer + buffer->size - buffer->trampolines_size;
  size_t gen_c_size = relocCode(gen_loc);
  assert(minSize == getOffset());
  assert(gen_c_size == size); // relocCode always returns the size regardless of how much it actually ends up using

  assert(trampolines_used <= size - minSize);

  buffer->trampolines_size = old_trampolines_size + size;
  // void *gen_loc2 = buffer->buffer + buffer->size - buffer->trampolines_size - size;
  // buffer->trampolines_size += minSize;
  // assert(gen_loc == (void*)(buffer->buffer + buffer->size - buffer->trampolines_size));

  CodeBuffer ret((mem_loc_t)gen_loc, minSize);
  ret.can_write_buffer = true;
  if(trampolines_used) {
    ret.external_trampolines_size += trampolines_used;
    ret.external_trampolines = gen_tramp - trampolines_used;
  }
  buffer = NULL;
  return ret;
}

void SimpleCompiler::write_restore_registers(uint64_t restore) {
  //uint64_t restore = clobbered_registers;
  int indx = 0;
  while(restore) {
    if(restore & 0x1) {
      mov(get_asm_register_from_sys(indx), x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + indx * 8 - move_stack_by));
    }
    restore >>= 1;
    indx++;
  }
}

void SimpleCompiler::restore_registers() {
  write_restore_registers(clobbered_registers);
  clobbered_registers = 0;
}


void SimpleCompiler::protect_register(int id) {
  if((clobbered_registers & (1 << id)) == 0) {
    mov(x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + id * 8 - move_stack_by), get_asm_register_from_sys(id));
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
    indx++;
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
  // auto offset = getOffset();
  // setCursor((uint8_t*)addr);
  // bind(label);
  // setOffset(offset);

  LabelData* data = getLabelData(label);
  assert(data->offset == -1);
  // assert(data->links == NULL);

  assert(data->exId == 0);
  data->exId = 0xAB0ADD00;
  data->exData = (void*)addr;

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

CodeBuffer SimpleCompiler::TestRegister(mem_loc_t resume_pc, int reg, register_t val, tracer_merge_block_stack_s *merge_addr, uint32_t _comp_op) {
  auto r = get_register(reg);
  asmjit::X86GpReg scr;
  if(val > 0x7fffffff)
    scr = get_scratch_register();
  //Label success = newLabel();
  Label failure = newLabel();
  SimpleCompiler resume_block(buffer);
  resume_block.clobbered_registers |= clobbered_registers;
  resume_block.popf();
  resume_block.ResumeBlockJump(resume_pc);

  auto resume_cb = resume_block.finalize_bottom();
  set_label_address(failure, resume_cb.getRawBuffer());

  do_merge_addr(resume_cb, merge_addr);

  pushf();
  if(val > 0x7fffffff) {
    mov(scr, imm_u(val));
    cmp(r, scr);
  } else {
    cmp(r, imm_u(val));
  }
  //jne(failure);
  emit(_comp_op, failure);
  popf();
  //jmp(imm_u(0xfafafafafafafafa));
  // jmp(failure);
  // bind(success);
  // popf();
  return resume_cb;
}

CodeBuffer SimpleCompiler::TestMemoryLocation(mem_loc_t resume_pc, mem_loc_t where, register_t val, tracer_merge_block_stack_s *merge_addr) {
  //Label success = newLabel();

  Label failure = newLabel();
  auto scr = get_scratch_register();
  asmjit::X86GpReg scr2;
  if(val > 0x7fffffff)
    scr2 = get_scratch_register();

  SimpleCompiler resume_block(buffer);
  resume_block.clobbered_registers |= clobbered_registers;
  resume_block.popf();
  resume_block.ResumeBlockJump(resume_pc);

  auto resume_cb = resume_block.finalize_bottom();
  set_label_address(failure, resume_cb.getRawBuffer());

  do_merge_addr(resume_cb, merge_addr);

  pushf();
  mov(scr, imm_ptr(where));
  if(val > 0x7fffffff) {
    mov(scr2, imm_u(val));
    cmp(x86::word_ptr(scr), scr2);
  } else {
    cmp(x86::word_ptr(scr), imm_u(val));
  }
  jne(failure);
  popf();
  // jmp(failure); // TODO: bind this label
  // bind(success);
  // popf();
  return resume_cb;
}

CodeBuffer SimpleCompiler::TestOperand(mem_loc_t resume_pc, const asmjit::Operand& opr, register_t val, tracer_merge_block_stack_s *merge_addr) {
  Label failure = newLabel();
  asmjit::X86GpReg scr, scr2;
  scr = get_scratch_register();
  if(val > 0x7fffffff)
    scr2 = get_scratch_register();

  // TODO: manage of the opr is loaded depending on the size of it?
  //assert(opr.getSize() <= 4);

  SimpleCompiler resume_block(buffer);
  resume_block.clobbered_registers |= clobbered_registers;
  resume_block.popf();
  resume_block.ResumeBlockJump(resume_pc);

  auto resume_cb = resume_block.finalize_bottom();
  set_label_address(failure, resume_cb.getRawBuffer());
  do_merge_addr(resume_cb, merge_addr);

  pushf();
  // mov(src, opr);
  emit(kX86InstIdMov, scr, opr);
  if(val > 0x7fffffff) {
    mov(scr2, imm_u(val));
    cmp(scr, scr2);
  } else {
    cmp(scr, imm_u(val));
  }

  jne(failure);
  popf();

  return resume_cb;
}

uint64_t* SimpleCompiler::MakeCounter() {
  uint64_t *cptr = (uint64_t*)(buffer->buffer + buffer->size - buffer->trampolines_size - sizeof(uint64_t));
  *cptr = 0;
  buffer->trampolines_size += sizeof(uint64_t);
  auto label = newLabel();
  set_label_address(label, (mem_loc_t)cptr);
  //auto scr = get_scratch_register();
  //auto scr2 = get_scratch_register();
  //mov(scr2, imm_ptr(cptr));
  // mov(scr, x86::ptr(label));
  // inc(scr);
  // mov(x86::ptr(label), scr);

  // TODO: make this add to this location
  //auto op = x86::ptr_abs((Ptr)cptr);
  auto op = x86::ptr(label);
  op.setSize(8);
  inc(op);  // use inc instead of add since this won't change the eflags
  //add(op, 1);
  //assert(0);

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

void SimpleCompiler::Push64bitValue(uint64_t value) {
  // auto label = newLabel();
  // uint64_t *cptr = (uint64_t*)(buffer->buffer + buffer->size - buffer->trampolines_size - sizeof(uint64_t));
  // *cptr = value;
  // buffer->trampolines_size += sizeof(uint64_t);
  // set_label_address(label, (mem_loc_t)cptr);

//   // this will get signed extended etc, so we will clean this up with a mov....because f-me
//   push(imm_u(value));
//   //movd(x86::ptr(x86::rsp, 4), imm_u(static_cast<uint32_t>(value >> 32)));
//   emit(kX86InstIdMovd, x86::ptr(x86::rsp, 4), imm_u(static_cast<uint32_t>(value >> 32)));
//
  if(value <= 0x7fffffff) {
    // this will fit, and not get sign extended
    push(imm_u(value));
  } else {
    // f-it, using an extra register to load in the value that we want to push
    // TODO: make this more efficent?
    auto scr = get_scratch_register();
    mov(scr, imm_u(value));
    push(scr);
    move_stack_by -= 8;
  }

}

CodeBuffer SimpleCompiler::ConditionalJump(mem_loc_t resume_pc, enum asmjit::X86InstId mnem, tracer_merge_block_stack_s *merge_addr) {
  CodeBuffer rb = MakeResumeTraceBlock(resume_pc, merge_addr);
  auto label = newLabel();
  set_label_address(label, rb.getRawBuffer());
  emit(mnem, label);
  return rb;
}


extern "C" void red_asm_restart_trace();

CodeBuffer SimpleCompiler::MakeResumeTraceBlock(mem_loc_t resume_pc, tracer_merge_block_stack_s *merge_addr) {
  SimpleCompiler resume_block(buffer);
  //resume_block.clobbered_registers |= clobbered_registers;
  resume_block.ResumeBlockJump(resume_pc);
  auto ret = resume_block.finalize_bottom();
  do_merge_addr(ret, merge_addr);
  return ret;
}

void SimpleCompiler::do_merge_addr(CodeBuffer &buff, tracer_merge_block_stack_s *merge_block) {
  mem_loc_t* ma = buff.find_stump<mem_loc_t>(0xfbfbfbfbfbfbfbfb);
  // make a linked list out of address where we are going to write this merge address
  *ma = merge_block->merge_head;
  merge_block->merge_head = (mem_loc_t)ma;
}

void SimpleCompiler::ResumeBlockJump(mem_loc_t resume_pc) {
  restore_registers();
  auto label_top = newLabel();
  auto label = newLabel();
  bind(label);
  jmp(label_top); // this should be exactly 5 bytes long with the destination address being the last part
  bind(label_top);
  mov(x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + 216), x86::r10);
  mov(x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + 224), x86::r9);
  mov(x86::ptr(x86::rsp, -TRACE_STACK_OFFSET + 232), x86::r8);
  mov(x86::r10, imm_u(resume_pc));
  // TODO: have this load the address of the instruction that jumped here instead of just this block
  // this will allow for it to easily write in a direct jump, as being designed now, we will have to redirect the jump through this indirection
  // so first conditional jump followed by direct jump
  // also, this will not work with concurrent threads
  lea(x86::r9, x86::ptr(label));
  mov(x86::r8, imm_u(0xfbfbfbfbfbfbfbfb));

  jmp(imm_ptr(&red_asm_restart_trace));

  // for identifying which instruction it jumped from
  mov(x86::r9, imm_u(0xfafafafafafafafa));

  // No one is going to generate code after this since we have already used a jump so there is no point
  // we also know that this will be generated at the bottom since there is no point of generating at the top
  // thus we use this information to ensure that the address of the jump is aligned to a 4byte boundary which means that it
  // can be atomically updated (hopefully)

  auto loffset = getLabelOffset(label_top);

  mem_loc_t laddr = (mem_loc_t)(buffer->buffer + buffer->size - buffer->trampolines_size - getCodeSize() + loffset);

  for(int i = laddr & 0x3; i; i--) {
    nop();
  }

  mem_loc_t laddr2 = (mem_loc_t)(buffer->buffer + buffer->size - buffer->trampolines_size - getCodeSize() + loffset);

  assert((laddr2 & 0x3) == 0);
  //assert(0);
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
  //assert(_dst == (void*)buffer_cursor);

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


  // manage labels that are linked to absolute addresses
  size_t labelCount = _labels.getLength();

  for(size_t i = 0; i < labelCount; i++) {
    if(_labels[i]->exId == 0xAB0ADD00) {
      uint8_t *target = (uint8_t*)_labels[i]->exData;
      // check that in the same 4gb memory block
      // if(((uint64_t)target & 0xffffffff00000000) != ((uint64_t)dst & 0xffffffff00000000)) {
      //   red_printf("failed same region check %#016lx %#016lx\n", target, dst);
      //   assert(0);
      // }
      int64_t buf_offset_l = target - dst;
      int32_t buf_offset = buf_offset_l; //target - dst;
      assert(buf_offset == buf_offset_l);
      LabelLink *link = _labels[i]->links;
      // LabelLink *prev = nullptr;
      while(link) {
        if(link->relocId != -1) {
          assert(0); // TODO:
        } else {
          int32_t patchValue = static_cast<int32_t>(buf_offset - link->offset + link->displacement);

          uint32_t patchSize = readU8At(link->offset);
          assert(patchSize == 4);

          Utils::writeI32u(dst + link->offset, patchValue);
        }
        // prev = link;
        link = link->prev;
      }
      // if(prev) {
      //   prev->prev = _unusedLinks;
      //   const_cast<SimpleCompiler*>(this)->_unusedLinks = _labels[i]->links;
      //   _labels[i]->links = nullptr;
      // }
    }
  }


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
