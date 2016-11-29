
// useful for compiling against while not causing any "problems"
//#define DISABLE_REDMAGIC

// this is define in a .c file instead of .s so that we can
// interface with the -fPIC methods & macros, also need to have @plt at the end

#ifndef DISABLE_REDMAGIC

__asm__("jmp_rax: \n"
        "pop %rsi \n"
        "jmp *%rax \n"
        );

#define USER_INTERFACE(method)                       \
  __asm__(".text \n"                                 \
          ".global redmagic_" #method "\n"           \
          ".type redmagic_" #method ",@function \n"  \
          ".align 16 \n"                             \
          "redmagic_" #method ": \n"                 \
          "movq 0(%rsp), %rsi \n"                    \
          "movq %rsp, %rdx \n"                       \
          "pushq $0 \n"                              \
          "call red_user_" #method "@plt \n"         \
          "popq %rdi \n"                             \
          "cmp $5, %rax \n"                          \
          "jg jmp_rax \n"                            \
          "ret \n"                                   \
          );

#else
#define USER_INTERFACE(method)                       \
  __asm__(".text \n"                                 \
          ".global redmagic_" #method "\n"           \
          ".type redmagic_" #method ",@function \n"  \
          ".align 16 \n"                             \
          "redmagic_" #method ": \n"                 \
          "ret \n"                                   \
          );

#endif

#pragma GCC visibility push(default)

USER_INTERFACE(force_begin_trace);
USER_INTERFACE(force_end_trace);
USER_INTERFACE(force_jump_to_trace);
USER_INTERFACE(backwards_branch);
USER_INTERFACE(fellthrough_branch);
USER_INTERFACE(ensure_not_traced);
USER_INTERFACE(temp_disable);
USER_INTERFACE(temp_enable);
USER_INTERFACE(is_traced);
USER_INTERFACE(begin_merge_block);
USER_INTERFACE(end_merge_block);
USER_INTERFACE(begin_branchable_frame);
USER_INTERFACE(end_branchable_frame);

#pragma GCC visibility pop
