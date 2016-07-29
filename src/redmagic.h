/**
 * Red Magic by Matthew Francis-Landau <matthew@matthewfl.com>
 */

#ifndef REDMAGIC_H_
#define REDMAGIC_H_


#ifdef __cplusplus
extern "C" {
#endif

// to be call as at the start of main
void redmagic_start(void);

// indicates that we have a backwards branch somewhere, determine if worth tracing
void redmagic_backwards_branch(void *);

// we were at a backwards branch instruction but didn't take it
void redmagic_fellthrough_branch(void *);

// control forcing an the JIT to start a trace of this thread
void redmagic_force_begin_trace(void *);
void redmagic_force_end_trace(void *);

void redmagic_force_jump_to_trace(void *);

// make sure that the program is currently not being traced
// use before error handling/random inline returns
void redmagic_ensure_not_traced(void);


// temporarly disable JIT in a given method
// must have an accompany enable call for every disable otherwise the internal state may go wrong...
void redmagic_temp_disable(void);
void redmagic_temp_enable(void);

// for setup to tell the jit to not trace some function, eg the call into a gc or some custom malloc
void redmagic_do_not_trace_function(void* function_pointer);

// disable traceing on a specific branch, eg if there is some disallowed instruction such as yield contained in the branch
void redmagic_disable_branch(void *);

// return 0 if not traced, non zero otherwise
unsigned long redmagic_is_traced(void);

// A merge block allows you to have some section of code that performs branches but at the end of the block merge back into the same instruction stream
// useful for things like reference counting where hitting zero will not have a significant impact on the following control flow
void redmagic_begin_merge_block(void);
void redmagic_end_merge_block(void);

#ifdef __cplusplus
}

class redmagic_disable {
public:
  redmagic_disable () { redmagic_temp_disable(); }
  ~redmagic_disable() { redmagic_temp_enable(); }
};

class redmagic_merge {
public:
  redmagic_merge () { redmagic_begin_merge_block(); }
  ~redmagic_merge() { redmagic_end_merge_block(); }
};

#endif




#endif // REDMAGIC_H_
