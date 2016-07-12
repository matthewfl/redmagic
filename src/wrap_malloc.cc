#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <new>

// we can't direclty use allocators when we are tracing since it might screw with their internal states

#define NBUFFERS 6

#define BUFFER_SIZES(X)                         \
  X(1024);                                      \
  X(4096);                                      \
  X(8192);

#define MALLOC_BUFFERS(SIZE)                                \
  __thread uint8_t allocated_ ## SIZE[NBUFFERS];            \
  __thread uint8_t buffer_ ## SIZE[NBUFFERS][SIZE];

BUFFER_SIZES(MALLOC_BUFFERS);

size_t largest_malloc = 0;

namespace redmagic {
  extern thread_local bool is_traced;
}
using namespace redmagic;

extern "C" void *__real_malloc(size_t size);

extern "C" void *__wrap_malloc(size_t size) {
  if(size > largest_malloc)
    largest_malloc = size;

  if(!is_traced)
    return __real_malloc(size);

#define FIND_BUFFER(SIZE)                                   \
  if(size < SIZE) {                                         \
    for(int i = 0; i < sizeof(buffer_##SIZE) / SIZE; i++) { \
      if(allocated_##SIZE[i] == 0) {                        \
        allocated_##SIZE[i] = 1;                            \
        return buffer_##SIZE[i];                            \
      }                                                     \
    }                                                       \
  }

  BUFFER_SIZES(FIND_BUFFER);

 use_real_malloc:
  printf("============trying to use real malloc\n");
  abort();

  return __real_malloc(size);
}

extern "C" void __real_free(void *ptr);

extern "C" void __wrap_free(void *ptr) {
#define FREE_BUFFER(SIZE)                                               \
  if(ptr >= (void*)buffer_##SIZE && ptr <= (void*)((uint8_t*)buffer_##SIZE + sizeof(buffer_##SIZE))) { \
    int i = ((uint8_t*)ptr - (uint8_t*)&buffer_##SIZE) / SIZE;          \
    assert(allocated_##SIZE[i] == 1);                                   \
    allocated_##SIZE[i] = 0;                                            \
    return;                                                             \
  }

  BUFFER_SIZES(FREE_BUFFER);

  if(is_traced)
    printf("more wtf\n");
  __real_free(ptr);
}


extern "C" void *__real_realloc(void *ptr, size_t size);

extern "C" void *__wrap_realloc(void *ptr, size_t size) {
  if(size > largest_malloc)
    largest_malloc = size;
#define REALLOC_BUFFER(SIZE)                                            \
  if(ptr >= (void*)buffer_##SIZE && ptr <= (void*)((uint8_t*)buffer_##SIZE + sizeof(buffer_##SIZE))) { \
    if(size < SIZE)                                                     \
      return ptr;                                                       \
    abort();                                                            \
  }

  BUFFER_SIZES(REALLOC_BUFFER);

  return __real_realloc(ptr, size);
}

extern "C" void *__real_calloc(size_t mnemb, size_t size);

extern "C" void *__wrap_calloc(size_t mnemb, size_t size) {
  // TODO:?
  // isn't used by asmjit
  abort();
  return __real_calloc(mnemb, size);
}


void* operator new(std::size_t v) _GLIBCXX_THROW (std::bad_alloc)
//  __attribute__((__externally_visible__))
{ return __wrap_malloc(v); }
void* operator new[](std::size_t v) _GLIBCXX_THROW (std::bad_alloc)
//  __attribute__((__externally_visible__))
{ return __wrap_malloc(v); }
void operator delete(void* v) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__))
{ __wrap_free(v); }
void operator delete[](void* v) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__))
{ __wrap_free(v); }
#if __cpp_sized_deallocation
void operator delete(void* v, std::size_t) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__))
{ __wrap_free(v); }
void operator delete[](void* v, std::size_t) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__))
{ __wrap_free(v); }
#endif
void* operator new(std::size_t v, const std::nothrow_t&) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__));
{ return __wrap_malloc(v); }
void* operator new[](std::size_t v, const std::nothrow_t&) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__));
{ return __wrap_malloc(v); }
void operator delete(void* v, const std::nothrow_t&) _GLIBCXX_USE_NOEXCEPT
//__attribute__((__externally_visible__));
{ __wrap_free(v);}
void operator delete[](void* v, const std::nothrow_t&) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__));
{ __wrap_free(v); }
#if __cpp_sized_deallocation
void operator delete(void* v, std::size_t, const std::nothrow_t&) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__));
{ __wrap_free(v); }
void operator delete[](void* v, std::size_t, const std::nothrow_t&) _GLIBCXX_USE_NOEXCEPT
//  __attribute__((__externally_visible__));
{ __wrap_free(v); }
#endif
