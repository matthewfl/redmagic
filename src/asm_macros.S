/**
  * argument registers:  rdi, rsi, rdx, rcx, r8, r9
  * preserve registers: rbx, rsp, rbp, r12, r13, r14, r15
  * scratch registers: rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11
  *
  * N.L represents a new line in the macro expansion
  */

#include "constants.h"

  ////////////////////////////////////////////////////
  .macro  m_push_all_regs
  // should match sys/regs.h, sys/user.h
  // 216 bytes for the struct, and then offset by 512 from the current stack
  movq %r15, (-TRACE_STACK_OFFSET + 0)(%rsp)
  movq %r14, (-TRACE_STACK_OFFSET + 8)(%rsp)
  movq %r13, (-TRACE_STACK_OFFSET + 16)(%rsp)
  movq %r12, (-TRACE_STACK_OFFSET + 24)(%rsp)
  movq %rbp, (-TRACE_STACK_OFFSET + 32)(%rsp)
  movq %rbx, (-TRACE_STACK_OFFSET + 40)(%rsp)
  movq %r11, (-TRACE_STACK_OFFSET + 48)(%rsp)
  movq %r10, (-TRACE_STACK_OFFSET + 56)(%rsp)
  movq %r9,  (-TRACE_STACK_OFFSET + 64)(%rsp)
  movq %r8,  (-TRACE_STACK_OFFSET + 72)(%rsp)
  movq %rax, (-TRACE_STACK_OFFSET + 80)(%rsp)
  movq %rcx, (-TRACE_STACK_OFFSET + 88)(%rsp)
  movq %rdx, (-TRACE_STACK_OFFSET + 96)(%rsp)
  movq %rsi, (-TRACE_STACK_OFFSET + 104)(%rsp)
  movq %rdi, (-TRACE_STACK_OFFSET + 112)(%rsp)


  // using add/sub before this point will cause the eflags to change
  // which we don't want, so save what ever was on the stack in the first place
  // push the eflags and then restore the stack to what it was before
  popq %r15
  pushf
  popq %r14
  push %r15
  movq %r14, (-TRACE_STACK_OFFSET + 144)(%rsp)

  // now that the eflags are saved, we can use sub
  sub $TRACE_STACK_OFFSET, %rsp

  // orig rax 120
  // rip 128
  xor %r14, %r14
  movq %r14, 136(%rsp)
  mov %cs, 136(%rsp)

  mov %rsp, %r15
  add $TRACE_STACK_OFFSET, %r15
  // make the stored value of rsp contain where the stack actually ends
  // this makes the restore at the end easier to write
  movq %r15, 152(%rsp)

  movq %r14, 160(%rsp)
  mov %ss, 160(%rsp)
  // fsbase 168
  // gsbase 176

  movq %r14, 184(%rsp)
  movq %r14, 192(%rsp)
  movq %r14, 200(%rsp)
  movq %r14, 208(%rsp)

  mov %ds, 184(%rsp)
  mov %es, 192(%rsp)
  mov %fs, 200(%rsp)
  mov %gs, 208(%rsp)

  // 208 == 0xd0
  // extra registers....
  // make sure that the region we are going to save these too is aligned to 16 byte boundary
  movq %rsp, %rax
  // yes this is add instead of a subtract even though this is on the stack (we are "lower" on the stack then the regs struct)
  //add $16, %rax // just include this add in the offset of fxsaveq
  and $~15, %rax

  fxsaveq 0x180(%rax)

  .endm

  //////////////////////////////////////////////////
  .macro m_pop_all_regs

  // extra registers
  movq %rsp, %rax
  and $~15, %rax
  fxrstorq 0x180(%rax)

  // eflags
  movq 144(%rsp), %r14
  popq %r15
  pushq %r14
  popf
  pushq %r15

  // can not use add/sub past this point due to the eflags being set

  movq 0(%rsp),  %r15
  movq 8(%rsp),  %r14
  movq 16(%rsp), %r13
  movq 24(%rsp), %r12
  movq 32(%rsp), %rbp
  movq 40(%rsp), %rbx
  movq 48(%rsp), %r11
  movq 56(%rsp), %r10
  movq 64(%rsp), %r9
  movq 72(%rsp), %r8
  movq 80(%rsp), %rax
  movq 88(%rsp), %rcx
  movq 96(%rsp), %rdx
  movq 104(%rsp), %rsi
  movq 112(%rsp), %rdi
  // orig rax 120
  // rip 128

  // illegal instruction
  //mov 136(%rsp), %cs

  // eflags above

  //movq %rsp, 152(%rsp)
  //mov 160(%rsp), %ss
  // fsbase 168
  // gsbase 176

  //mov 184(%rsp), %ds
  //mov 192(%rsp), %es
  //mov 200(%rsp), %fs
  //mov 208(%rsp), %gs

  // the correct address is already computed in here
  // so we don't need to adjust it any more
  movq 152(%rsp), %rsp

  .endm


  // [all cap name, %reg name, reg struct offset]
#define MAIN_REGISTERS(METHOD)  \
  METHOD(R15, %r15, 0)        \
  MAIN_REGISTERS_NOT_R15(METHOD)

#define MAIN_REGISTERS_NOT_R15(METHOD) \
  METHOD(R14, %r14, 8)        \
  METHOD(R13, %r13, 16)       \
  METHOD(R12, %r12, 24)       \
  METHOD(RBP, %rbp, 32)       \
  METHOD(RBX, %rbx, 40)       \
  METHOD(R11, %r11, 48)       \
  METHOD(R10, %r10, 56)       \
  METHOD(R9,  %r9,  64)       \
  METHOD(R8,  %r8,  72)       \
  METHOD(RAX, %rax, 80)       \
  METHOD(RCX, %rcx, 88)       \
  METHOD(RDX, %rdx, 96)       \
  METHOD(RSI, %rsi, 104)      \
  METHOD(RDI, %rdi, 112)
