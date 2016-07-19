
//#define DISABLE_REDMAGIC

// this is define in a .c file instead of .s so that we can
// interface with the -fPIC methods, also need to have @plt at the end

#ifndef DISABLE_REDMAGIC

__asm__("jmp_rax: \n"
        "add $8, %rsp \n"
        "jmp *%rax \n"
        );

#define USER_INTERFACE(method)                  \
  __asm__(".text \n"                            \
          ".global redmagic_" #method "\n"      \
          ".type redmagic_" #method ",@function \n"  \
          ".align 16 \n"                             \
          "redmagic_" #method ": \n"                 \
          "movq 0(%rsp), %rsi \n"               \
          "call red_user_" #method "@plt \n"    \
          "test %rax, %rax \n"                  \
          "jnz jmp_rax \n"                      \
          "ret \n"                              \
          );

#else
#define USER_INTERFACE(method)                  \
  __asm__(".text \n"                            \
          ".global redmagic_" #method "\n"      \
          ".type redmagic_" #method ",@function \n"  \
          ".align 16 \n"                             \
          "redmagic_" #method ": \n"            \
          "ret \n"                              \
          );

#endif

USER_INTERFACE(force_begin_trace);
USER_INTERFACE(force_end_trace);
USER_INTERFACE(force_jump_to_trace);
USER_INTERFACE(backwards_branch);
USER_INTERFACE(fellthrough_branch);
USER_INTERFACE(ensure_not_traced);
USER_INTERFACE(temp_disable);
USER_INTERFACE(temp_enable);
