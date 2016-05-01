#ifndef REDMAGIC_H_
#define REDMAGIC_H_

#ifdef __cplusplus
extern "C" {
#endif


// to be call as at the start of main
void redmagic_start();

// indicates that we have a backwards branch somewhere, determine if worth tracing
void redmagic_backwards_branch(void *);

// control forcing an the JIT to start a trace of this thread
void redmagic_force_begin_trace();
void redmagic_force_end_trace();



#ifdef __cplusplus
}
#endif


#endif // REDMAGIC_H_
