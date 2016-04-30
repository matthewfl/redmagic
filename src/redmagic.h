#ifndef REDMAGIC_H_
#define REDMAGIC_H_

#ifdef __cplusplus
extern "C" {
#endif

// struct representing an instance of red magic and all traces
struct redmagic_handle_t;
struct redmagic_thread_trace_t;

// init red magic
struct redmagic_handle_t *redmagic_init();
// destroy instance
void redmagic_destroy(struct redmagic_handle_t*);

// force starting a trace on this thread
struct redmagic_thread_trace_t *redmagic_start_trace(struct redmagic_handle_t*);



// global instance of red magic
extern struct redmagic_handle_t *redmagic_global_default;




#ifdef __cplusplus
}
#endif


#endif // REDMAGIC_H_
