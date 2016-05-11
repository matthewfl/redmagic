/**
 * Red Magic by Matthew Francis-Landau <matthew@matthewfl.com>
 */

#ifndef REDMAGIC_H_
#define REDMAGIC_H_


#ifdef __cplusplus
extern "C" {
#endif

#define REDMAGIC_NOINLINE
  //__attribute__ ((noinline)) __attribute__ ((visibility ("default")))


// to be call as at the start of main
void REDMAGIC_NOINLINE redmagic_start();

// indicates that we have a backwards branch somewhere, determine if worth tracing
void REDMAGIC_NOINLINE redmagic_backwards_branch(void *);

// control forcing an the JIT to start a trace of this thread
void REDMAGIC_NOINLINE redmagic_force_begin_trace(void *);
void REDMAGIC_NOINLINE redmagic_force_end_trace(void *);

void REDMAGIC_NOINLINE redmagic_force_jump_to_trace(void *);


// temporarly disable JIT in a given method
// must have an accompany enable call for every disable otherwise the internal state may go wrong...
void REDMAGIC_NOINLINE redmagic_temp_disable();
void REDMAGIC_NOINLINE redmagic_temp_enable();


#ifdef __cplusplus
}

class redmagic_disable {
public:
  redmagic_disable () { redmagic_temp_disable(); }
  ~redmagic_disable() { redmagic_temp_enable(); }
};

#endif




#endif // REDMAGIC_H_
