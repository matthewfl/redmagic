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
