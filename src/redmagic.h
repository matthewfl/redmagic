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


#ifdef __cplusplus
}

class redmagic_disable {
public:
  redmagic_disable () { redmagic_temp_disable(); }
  ~redmagic_disable() { redmagic_temp_enable(); }
};

#endif




#endif // REDMAGIC_H_
