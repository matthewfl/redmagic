
#define TRACE_STACK_OFFSET 0x08ff /* hardcode offset from this base stack */

#define TRACE_RESUME_ADDRESS_OFFSET 0x0800 /* hardcode offset to find jump to loc */

// asmjit has some methods that use as much as 14k stack space,
// plus many objects are getting allocated on the stack to avoid allocations while running
#define TRACE_STACK_SIZE (64*1024)
