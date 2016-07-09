#include "asm_macros.S"


  .global red_asm_pop_stack_start
  .global red_asm_pop_stack_end
red_asm_pop_stack_start:
  add $8, %rsp
red_asm_pop_stack_end:

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


  .global red_asm_call_direct_start
  .global red_asm_call_direct_end
red_asm_call_direct_start:
  call *1f(%rip)
  jmp 2f
1:
  .byte 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa
2:
red_asm_call_direct_end:

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


#define MAKE_SET_BLOCK(CNAME, RNAME, OFFSET)     \
  .global red_asm_set_reg_ ## CNAME ## _start NL \
  .global red_asm_set_reg_ ## CNAME ## _end   NL \
red_asm_set_reg_ ## CNAME ## _start:          NL \
  movq $0xfafafafafafafafa, RNAME             NL \
red_asm_set_reg_ ## CNAME ## _end:            NL NL

  MAIN_REGISTERS(MAKE_SET_BLOCK)


#define MAKE_TEST_REG_BLOCK(CNAME, RNAME, OFFSET) \
  .global red_asm_test_reg_ ## CNAME ## _start NL \
  .global red_asm_test_reg_ ## CNAME ## _end   NL \
red_asm_test_reg_ ## CNAME ## _start:          NL \
  pushf                                        NL \
  test RNAME, 1f(%rip)                         NL \
  je 10f                                       NL \
  popf                                         NL \
  jmp *2f(%rip)                                NL \
1: /* compare register to */                   NL \
  .byte 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa, 0xfa  NL \
2: /* where to jump on failure */              NL \
  .byte 0xfb, 0xfb, 0xfb, 0xfb, 0xfb, 0xfb, 0xfb, 0xfb  NL \
10:                                            NL \
  popf                                         NL \
red_asm_test_reg_ ## CNAME ## _end:            NL NL

MAIN_REGISTERS(MAKE_TEST_REG_BLOCK)


#define MAKE_WRITE_REG_TO_ADDR(CNAME, RNAME, OFFSET) \
  .global red_asm_write_reg_to_addr_ ## CNAME ## _start NL \
  .global red_asm_write_reg_to_addr_ ## CNAME ## _end   NL \
red_asm_write_reg_to_addr_ ## CNAME ## _start:          NL \
  movq %r15, -728(%rsp)                                 NL \
  movq $0xfafafafafafafafa, %r15                        NL \
  movq RNAME, (%r15)                                    NL \
  movq -728(%rsp), %r15                                 NL \
red_asm_write_reg_to_addr_ ## CNAME ## _end:            NL NL

MAIN_REGISTERS_NOT_R15(MAKE_WRITE_REG_TO_ADDR)

  .global red_asm_write_reg_to_addr_R15_start
  .global red_asm_write_reg_to_addr_R15_end
red_asm_write_reg_to_addr_R15_start:
  movq %r14, -728(%rsp)
  movq $0xfafafafafafafafa, %r14
  movq %r15, (%r14)
  movq -728(%rsp), %r14
red_asm_write_reg_to_addr_R15_end:


#define MAKE_READ_ADDR_TO_REG(CNAME, RNAME, OFFSET) \
  .global red_asm_write_mem_to_reg_ ## CNAME ## _start NL \
  .global red_asm_write_mem_to_reg_ ## CNAME ## _end   NL \
red_asm_write_mem_to_reg_ ## CNAME ## _start:          NL \
  movq %r15, -728(%rsp)                                 NL \
  movq $0xfafafafafafafafa, %r15                        NL \
  movq (%r15), RNAME                                    NL \
  movq -728(%rsp), %r15                                 NL \
red_asm_write_mem_to_reg_ ## CNAME ## _end:            NL NL

MAIN_REGISTERS_NOT_R15(MAKE_READ_ADDR_TO_REG)

  .global red_asm_write_mem_to_reg_R15_start
  .global red_asm_write_mem_to_reg_R15_end
red_asm_write_mem_to_reg_R15_start:
  movq %r14, -728(%rsp)
  movq $0xfafafafafafafafa, %r14
  movq (%r14), %r15
  movq -728(%rsp), %r14
red_asm_write_mem_to_reg_R15_end:


// we don't need executable stack
  .section .note.GNU-stack,"",%progbits
