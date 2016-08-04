#ifndef REDMAGIC_CONFIG_H_
#define REDMAGIC_CONFIG_H_


#ifdef RED_RELEASE
# define CONF_RELEASE_BUILD
#endif

#ifdef CONF_RELEASE_BUILD
# define
# define CONF_BUILD_TOGGLE(debug, release) release
#else
// configure the system to perform more traces to attempt to debug
# define CONF_DEBUG_BUILD
# define CONF_BUILD_TOGGLE(debug, release) debug
#endif


// the number of loops that are require to occure before it traces a loop
#define CONF_NUMBER_OF_JUMPS_BEFORE_TRACE CONF_BUILD_TOGGLE(50, 150)

// redmagic will attempt inline forward jumps which is useful in cases like: `if(a || b || c...)` where many conditional jumps
// will merge to the same point, but it may require back tracking in a lot of cases which may be slower
//#define CONF_ATTEMPT_FORWARD_JUMP_INLINE
// ^^^ There is some issue with this, it causes ipython to crash....have already spent a lot of time trying to trace down the issue

// backward jumps that are inside the same generated block will be inlined, does _not_ require back tracking as the size of the block
// is know at the time the instruction is emitted, this is useful for sort loops eg: `while (a != NULL) a = a->next;`
#define CONF_ATTEMPT_BACKWARDS_JUMP_INLINE

// makes it print all the instructions processed and extra info
#ifdef CONF_DEBUG_BUILD
# define CONF_VERBOSE
#endif

// support aborting the system after some fixed number of instruction have been processed, see tools/bisect for debugging with this
#ifdef CONF_DEBUG_BUILD
# define CONF_GLOBAL_ABORT
#endif


// somehow python is not hitting the fellthrough trace for some traces that it starts
// unable to determine where it should actually be performing this, so we are just makeing the end of the branchable frame
// close out any traces that were created in this frame
// ^^^ this might have been a bug with the intergration, but now it is using this auto closing as a "feature"
#define CONF_ALLOW_UNCLOSED_TRACES


// using timers in addition to number of times it loops to determine what to trace
//#define CONF_USE_TIMERS
#define CONF_TIMER_DELAY_MS CONF_BUILD_TOGGLE(0, 5000)

#define CONF_ESTIMATE_INSTRUCTIONS

// instead of taking a trace all the way to the bottom of the loop, attempt to merge back at the ret inside of a method
// the idea being that most of the branches that we can end up helping will be inside the main interpreter loop
#define CONF_MERGE_BACK_ON_RET

//#define CONF_CHECK_RET_ADDRESS

#define CONF_CHECK_MERGE_RIP

#endif // REDMAGIC_CONFIG_H_
