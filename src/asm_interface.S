#include "asm_macros.S"



  .global red_asm_resume_tracer_block_start
  .global red_asm_resume_tracer_block_end
red_asm_resume_tracer_block_start:
  m_push_all_regs
  movq %rsp, %rax
  movq $0xfafafafafafafafa, %rsp
  movq 0(%rsp), %r12
  movq 8(%rsp), %r13
  movq 16(%rsp), %r14
  movq 24(%rsp), %r15
  movq 32(%rsp), %rbx
  movq 40(%rsp), %rbp

  movq 56(%rsp), %rsp

  ret
red_asm_resume_tracer_block_end:
  nop

  .global red_asm_resume_eval_block
red_asm_resume_eval_block:
  movq %rsp, 56(%rdi)

  movq %r12, 0(%rdi)
  movq %r13, 8(%rdi)
  movq %r14, 16(%rdi)
  movq %r15, 24(%rdi)
  movq %rbx, 32(%rdi)
  movq %rbp, 40(%rdi)

  movq %rsi, %rsp
  m_pop_all_regs
  jmpq *-TRACE_RESUME_ADDRESS_OFFSET(%rsp)


/*  .global red_asm_start_tracing
red_asm_start_tracing:
  // [null (old stack pointer), method_to_call, tracer_this, new_stack]
  m_push_all_regs
  movq %rsp, %rdi
  movq %rcx, %rsp
  jmp *%rsi
*/


  .global red_asm_compile_buff_near
red_asm_compile_buff_near:
  ret

  .global red_asm_begin_block
red_asm_begin_block:
  movq %rax, %rdi
  call *%rsi


// restart the trace on a bad branch inlined
  .global red_asm_restart_trace

red_asm_restart_trace:
  // the target rip has been put into r15
  m_push_all_regs
  // move the info into argument registers
  movq %r10, %rdi
  movq %r9, %rsi
  movq %rsp, %rdx

  // restore the origional values of r14&15
  movq 216(%rsp), %r10
  movq 224(%rsp), %r9
  movq %r10, 56(%rsp)
  movq %r9, 64(%rsp)

  call red_resume_trace@plt
  jmp *%rax




// we don't need executable stack
  .section .note.GNU-stack,"",%progbits
