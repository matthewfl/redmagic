#include "asm_macros.S"


  .global red_asm_pop_stack_start
  .global red_asm_pop_stack_end
red_asm_pop_stack_start:
  // this will end up chainging the eflags register
  // would be nice if there was a way to avoid doing that but still pop the stack
  // this should happen around method call returns so the value of eflags shouldn't matter in most cases....
  add $8, %rsp
red_asm_pop_stack_end:

/*
  .global red_asm_push_stack_start
  .global red_asm_push_stack_end
red_asm_push_stack_start:
  push 1f(%rip)
  jmp 2f
1:
  // this is probably bad
  // would be better to not use a jmp here
  // TODO: make the compiler allocate local enough space such
  // that we can access it, but far enough away that it isn't in the
  // instruction stream
  .byte 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa
2:
red_asm_push_stack_end:
  */



  .global red_asm_call_multiway_start
  .global red_asm_call_multiway_end
  .global red_asm_call_multiway_call_offset
red_asm_call_multiway_start:
  // push the return address
  push 10f(%rip)
  // give us a register to work with
  movq %r15, -728(%rsp)

  // complicated move instruction
  // will have to replace
  movq (%rax, %r13, 8), %r15

  // forward action
  test %r15, 11f(%rip)
  je 20f

  // first expected jump
  test %r15, 12f(%rip)
  jne 1f
  movq -728(%rsp), %r15
  jmp *13f(%rip)
1:

  test %r15, 14f(%rip)
  jne 2f
  movq -728(%rsp), %r15
  jmp *15f(%rip)
2:

  // our first guess and both alternates failed
  // leave the target function in %r15
  // the true value of %r15 will be at -720 now
red_asm_call_multiway_call_offset:
  call *16f(%rip)

10:
  // the return address
  .byte 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa
11:
  // the expected address if we continue
  .byte 0xfb, 0xfb, 0xfb, 0xfb, 0xfb, 0xfb, 0xfb, 0xfb
12:
  // address of first redirect
  .byte 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfc
13:
  // address of where to jump in this case
  .byte 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd
14:
  // address of second redirect
  .byte 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe
15:
  // address of where to jump in this case
  .byte 0xfe, 0xfe, 0xfe, 0xfe, 0xff, 0xff, 0xff, 0xff
16:
  // address to call to in the case that we have failed
  // to locate a sutable branch
  // either go back into the jit or another block with more branches
  .byte 0xfd, 0xfd, 0xfd, 0xfd, 0xff, 0xff, 0xff, 0xff
20:

  // return our scratch register to previous state
  movq -728(%rsp), %r15

red_asm_call_multiway_end:

/*
  .global red_asm_call_direct_start
  .global red_asm_call_direct_end
red_asm_call_direct_start:
  call *1f(%rip)
  jmp 2f
1:
  .byte 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa
2:
red_asm_call_direct_end:
*/
  .global red_asm_count_start
  .global red_asm_count_end
  .global red_asm_count_offset
red_asm_count_start:
  jmp 2f
1:
red_asm_count_offset:
  .byte 0,0,0,0,0,0,0,0
2:
  movq %r15, -728(%rsp)
  movq 1b(%rip), %r15
  inc %r15
  movq %r15, 1b(%rip)
  movq -728(%rsp), %r15
red_asm_count_end:


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

  .global red_asm_jump_rsi
red_asm_jump_rsi:
  jmp *%rsi

// we don't need executable stack
  .section .note.GNU-stack,"",%progbits
