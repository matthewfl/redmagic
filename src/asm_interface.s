/**
  * argument registers:  rdi, rsi, rdx, rcx, r8, r9
  * preserve registers: rbx, rsp, rbp, r12, r13, r14, r15
  * scratch registers: rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11
  */

  ////////////////////////////////////////////////////
  .macro  m_push_all_regs
  // should match the direction in sys/regs.h
  push %r15
  push %r14
  push %r13
  push %rbp
  push %rbx
  push %r11
  push %r10
  push %r9
  push %r8
  push %rax
  push %rcx
  push %rdx
  push %rsi
  push %rdi
  // orig rax??
  // push %rip (bad instruction)t
  // push %cs (bad instruction)
  sub $24, %rsp

  //push %eflags
  pushf

  // stack pointer? ignore
  push %rsp
  // push %ss (bad instruction)
  // fsbase (?)
  // gsbase (?)
  // push %ds (bad instruction)
  // push %es (bad instruction)
  sub $40, %rsp

  push %fs
  push %gs
  .endm

  //////////////////////////////////////////////////
  .macro m_pop_all_regs
  pop %gs
  pop %fs

  add $48, %rsp

  // ignore the stack pointer

  popf

  add $24, %rsp
  pop %rdi
  pop %rsi
  pop %rdx
  pop %rcx
  pop %rax
  pop %r8
  pop %r9
  pop %r10
  pop %r11
  pop %rbx
  pop %rbp
  pop %r13
  pop %r14
  pop %r15
  .endm



  .global red_asm_push_all_regs_start
  .global red_asm_push_all_regs_end
red_asm_push_all_regs_start:
  m_push_all_regs
red_asm_push_all_regs_end:


  .global red_asm_pop_all_regs_start
  .global red_asm_pop_all_regs_end
red_asm_pop_all_regs_start:
  m_pop_all_regs
red_asm_pop_all_regs_end:


  .global red_asm_resume_tracer_block_start
  .global red_asm_resume_tracer_block_end
red_asm_resume_tracer_block_start:
  sub $8, %rsp
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
  ret


  .global red_asm_return_to_block
red_asm_return_to_block:
  mov %rax, %rsp
  m_pop_all_regs
  ret

  .global red_asm_start_tracing
red_asm_start_tracing:
  // [null (old stack pointer), method_to_call, tracer_this, new_stack]
  sub $8, %rsp
  m_push_all_regs
  mov %rsp, %rdi
  mov %rcx, %rsp
  jmp *%rsi



  .global red_asm_compile_buff_near
red_asm_compile_buff_near:
  ret


// we don't need executable stack
  .section .note.GNU-stack,"",%progbits
