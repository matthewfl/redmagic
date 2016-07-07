/**
  * argument registers:  rdi, rsi, rdx, rcx, r8, r9
  * preserve registers: rbx, rsp, rbp, r12, r13, r14, r15
  * scratch registers: rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11
  */

  ////////////////////////////////////////////////////
  .macro  m_push_all_regs
  // should match sys/regs.h, sys/user.h
  // 216 bytes for the struct, and then offset by 512 from the current stack
  sub $728, %rsp

  movq %r15, 0(%rsp)
  movq %r14, 8(%rsp)
  movq %r13, 16(%rsp)
  movq %r12, 24(%rsp)
  movq %rbp, 32(%rsp)
  movq %rbx, 40(%rsp)
  movq %r11, 48(%rsp)
  movq %r10, 56(%rsp)
  movq %r9,  64(%rsp)
  movq %r8,  72(%rsp)
  movq %rax, 80(%rsp)
  movq %rcx, 88(%rsp)
  movq %rdx, 96(%rsp)
  movq %rsi, 104(%rsp)
  movq %rdi, 112(%rsp)
  // orig rax 120
  // rip 128
  xor %r14, %r14
  movq %r14, 136(%rsp)
  mov %cs, 136(%rsp)

  pushf
  pop %r15
  movq %r15, 144(%rsp)
  movq %rsp, 152(%rsp)

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

  .endm

  //////////////////////////////////////////////////
  .macro m_pop_all_regs

  // eflags
  movq 144(%rsp), %rax
  push %rax
  popf

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
  mov 136(%rsp), %cs

  // eflags above

  //movq %rsp, 152(%rsp)
  mov 160(%rsp), %ss
  // fsbase 168
  // gsbase 176
  mov 184(%rsp), %ds
  mov 192(%rsp), %es
  mov 200(%rsp), %fs
  mov 208(%rsp), %gs

  movq 152(%rsp), %rsp
  add $728, %rsp

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
  jmpq -448(%rsp)


  .global red_asm_start_tracing
red_asm_start_tracing:
  // [null (old stack pointer), method_to_call, tracer_this, new_stack]
  sub $8, %rsp
  m_push_all_regs
  movq %rsp, %rdi
  movq %rcx, %rsp
  jmp *%rsi



  .global red_asm_compile_buff_near
red_asm_compile_buff_near:
  ret

  .global red_asm_ret_only
red_asm_ret_only:
  ret


// we don't need executable stack
  .section .note.GNU-stack,"",%progbits
