  .global red_asm_push_const_to_stack_start
  .global red_asm_push_const_to_stack_end
red_asm_push_const_to_stack_start:
  // this assumes that the stack point is valid
  // which it might not be....so this could end up clobbering something

  mov %r15, -16(%rsp)
  movq $0xfafafafafafafafa, %r15
  push %r15
  mov -8(%rsp), %r15

red_asm_push_const_to_stack_end:

  .global red_asm_decrease_stack_addr_start
  .global red_asm_decrease_stack_addr_end
red_asm_decrease_stack_addr_start:
  add $0xfafa, %rsp
red_asm_decrease_stack_addr_end:
