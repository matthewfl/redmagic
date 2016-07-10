
// this is define in a .c file instead of .s so that we can
// interface with the -fPIC methods, also need to have @plt at the end
__asm__("jmp_rax: \n"
        "add $8, %rsp \n"
        "jmp *%rax \n"
        );

#define USER_INTERFACE(method)                  \
  __asm__(".global redmagic_" #method "\n"      \
          "redmagic_" #method ": \n"            \
          "movq 0(%rsp), %rsi \n"               \
          "call red_user_" #method "@plt \n"    \
          "test %rax, %rax \n"                  \
          "jnz jmp_rax \n"                      \
          "ret \n"                              \
          );

USER_INTERFACE(force_begin_trace);
USER_INTERFACE(force_end_trace);
USER_INTERFACE(force_jump_to_trace);
USER_INTERFACE(backwards_branch);
USER_INTERFACE(fellthrough_branch);
USER_INTERFACE(ensure_not_traced);
