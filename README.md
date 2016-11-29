# Redmagic

Redmagic is a tracing JIT for interpreters that are written in C/C++.  It operates by generating traces from observing x86_64 instruction execution and transparently switching between generated code and the interpreter loop.

### Tracing introduction

Tracing is a JIT technique which has been previously implemented in PyPy, Tracermonkey and other JITs.  It works by identifying loops in a program a these loops will represent the "hot spots" of the program as they are going to be executed a number of times during the programs life time. (eg a finite sized program without loops must terminate, loops are the only thing that can make the program's life extend longer)

To identify loops, it will track all *backwards jumps* at the bytecode level as this will indicate that the interpreted language is inside a loop.  The JIT will leave the loop when the backwards jump's condition is not meet and it will leave any optimized loop code when the loop's condition *fallsthrough*.



## API
See [src/redmagic.h](src/redmagic.h) for the JIT's public interface.

A small sample interpreter loop with redmagic integration is demoed in [src/main.cc](src/main.cc).

A full integration is show with [cPython](#python-int)

#### Basic API

`redmagic_start(void)`: Initializes redmagic's internal data structures, to be called inside main or before any other methods are called.

`redmagic_backwards_branch(void *id)`:  Indicates that the interpreter is taking a backwards branch which means that the user's program is starting a loop.  The argument `void *id` is an opaque reference which is used to reference a given loop inside the user's program.  This does not need to be a valid pointer to memory (can cast an int etc) but if this pointer is not unique to the loop referenced then this can cause erroneous behavior.

`redmagic_fellthrough_branch(void *id)`: Exits the JITed code.  The `id` **must** match the `id` that was passed to `redmagic_backwards_branch` otherwise this operation will be treated as a nop.

#### Disable tracing API

`redmagic_do_not_trace_function(void *function_pointer)`: There will often exits a number of methods which do not make since to inline as inlining them will not improve the performance of the user's program.  (Eg `malloc` will have a lot of internal branching and inlining it will not improve performance).

`redmagic_ensure_not_traced(void)`: There may be methods such as error handlers which do not make since to trace.  By placing this method call at the top of such methods, this will abort any currently running trace and ensure that the program is returned to executing normally.

`redmagic_disable_branch(void *id)`: If there is some loop which the JIT should not attempt to optimize, then passing that loop's `id` to this method will prevent any further attempts to optimize it.


##### Temp disable
Sometimes there are blocks such as I/O where it does not make since to perform tracing.  One option would be to extract all I/O operations into different methods and register these methods with `redmagic_do_not_trace_function`, alternately we can use Temp disable to create a block of code where tracing does not take place inside of any method.

```
// normal traced code
i = i + 2;
redmagic_temp_disable();

// this is not traced
printf("%l\n", i);
// ...

redmagic_temp_enable();
// resume the optimized traced code
i = i + 3;
```

#### Frames
In the case of recursion, it is possible that a loop ends up calling itself, which can make tracking its entry and exits difficult if it has the same `id`.  To counter this, branchable frames inform redmagic that a new stack frame is being pushed onto the stack.  This way, a loop will only "exit" if it receives a `redmagic_fellthrough_branch` at the correct stack depth.

```
// Push stack frame
unsigned long redmagic_frame_tracking;
redmagic_begin_branchable_frame(&redmagic_frame_tracking);

// exit stack frame
redmagic_end_branchable_frame(&redmagic_frame_tracking);
```

#### Merge blocks
There might be small branching operations which we want to inline, but do not want to reconstruct a complete trace of the user's program loop.  An example of this could be reference counting, where the operation of decrementing and checking a reference could end up generating two difference traces due to the difference in how a program's branch behaves.



```
// small operation that we want to inline in our trace but do not
// want the direction of this branch cause two different traces
// to be generated
redmagic_begin_merge_block();
if(--(obj->reference_count) == 0) {
  delete_obj(obj);
}
redmagic_end_merge_block();
// at this point, regardless of how any branches behaved in the
// previous block, they will merge back to the same generated trace
```


## Build instructions

build instructions:

    pacman -S strace python2
    git submodules update --init --recursive
    ./make release

build python:

    git clone https://github.com/matthewfl/cpython.git
    cd cpython
    git checkout redmagic3
    ln -s ../redmagic/src/redmagic.h .
    ln -s ../redmagic/build/libredmagic.so.* .
    ./configure --with-pydebug --prefix=/usr
    make


### Python integration <a name='python-int'></a>

There exists a partially complete implementation for cPython 2.7 [here](https://github.com/matthewfl/cpython/tree/redmagic3) ([diff](https://github.com/matthewfl/cpython/compare/116b7d5350970fbe330f4bc8e6985f01142cf8dd...matthewfl:redmagic3?expand=1)).
Compared to most other implementations of JITs for python, once can see that the modification to cPython is fairly small with only a handful of lines inside of the interpreter loop being annotated and


## Licence
license: LGPLv3


# TODO
### Bugs
* Redmagic can currently boot the standard python repl and work with a number of simple programs.  It can also start IPython repl, however it will usually crash after a few key presses.

### Performance issues
* When evaluating the traced program the system has to decode *all* instructions to determine if there is something that needs to be rewritten.  This includes all jumps and references to register `%rip` which will be changed when executing under the generated code.  Any instruction that is left unchanged will be simply `memcpy`ed over to the generation buffer while all other instructions will have to be further processed.  Further processing includes running the program up to the instruction in question, stopping the program, capturing the value of all of the program's registers, resuming redmagic's tracing mechanism, determining how the instruction in question would behave in this case, and finally generating appropriate code for a given instruction which might include trampolines to resume tracing in the case that a conditional check fails.  Given that a typical program can be expected to perform a branch every 15-100 instructions, there is an immense overhead to the tracing operation.
* Given the overhead of generating a trace, we should only trace methods for which we can justify performing a very slow tracing operation to avoid causing a program to degrade in performance.  ATM, redmagic only uses a counter to determine which loops should be traced, additional information such as estimated number of instructions involved in a loop should be incorporated.

### Optimizations
* ATM, the JIT does not perform any optimizations outside of replacing branches with a trace.  There are still a number of peephole optimizations which should be implemented to identify values which will not changed as a loop executes.
* Register aliasing should be used in place of accessing memory.  ATM the JIT does not identify when statements are accessing similar locations in memory which means that registers are being used suboptimally.
* Memory optimizations: Inside of a trace, the system should identify items which are allocated and then shortly deallocated (temporary values etc).


These optimizations are necessary as languages such as python have a high overhead with data structures and pointer dereferences which can have a higher overhead then the dispatch inside of the interpreter loop.
