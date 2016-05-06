# Assembly instructions that are needed

  .global   red_asm_temp_disable_trace
red_asm_temp_disable_trace:
  int3
  ret

  .global   red_asm_temp_enable_trace
red_asm_temp_enable_trace:
  int3
  ret

  .global   red_asm_end_trace
red_asm_end_trace:
  int3
  ret

  .global   red_asm_begin_trace
red_asm_begin_trace:
  int3
  ret


  .global red_asm_return_after_method_call
red_asm_return_after_method_call:
  # at this point we will replace the instruction pointer with where we should have returned to
  int3
  # this next line will never run
  jmp red_asm_return_after_method_call
