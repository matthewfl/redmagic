#ifndef REDMAGIC_CONFIG_H_
#define REDMAGIC_CONFIG_H_


// the number of loops that are require to occure before it traces a loop
#define CONF_NUMBER_OF_JUMPS_BEFORE_TRACE 10

// redmagic will attempt inline forward jumps which is useful in cases like: `if(a || b || c...)` where many conditional jumps
// will merge to the same point, but it may require back tracking in a lot of cases which may be slower
//#define CONF_ATTEMPT_FORWARD_JUMP_INLINE

// backward jumps that are inside the same generated block will be inlined, does _not_ require back tracking as the size of the block
// is know at the time the instruction is emitted, this is useful for sort loops eg: `while (a != NULL) a = a->next;`
#define CONF_ATTEMPT_BACKWARDS_JUMP_INLINE

// makes it print all the instructions processed an extra info
#define CONF_VERBOSE

// support aborting the system after some fixed number of instruction have been processed, see tools/bisect for debugging with this
#define CONF_GLOBAL_ABORT

#endif // REDMAGIC_CONFIG_H_
