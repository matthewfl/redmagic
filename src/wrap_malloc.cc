#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <sys/mman.h>


#include <new>

// we can't direclty use allocators when we are tracing since it might screw with their internal states

// use mmap and mprotect to wrap all alloc options
#define MPROTECTED_ALLOC (40*1024)

#define NBUFFERS 6

#define BUFFER_SIZES(X)                         \
  X(1024);                                      \
  X(4096);                                      \
  X(8192);                                      \
  X(16384);

#define MALLOC_BUFFERS(SIZE)                                \
  __thread uint8_t allocated_ ## SIZE[NBUFFERS];            \
  __thread uint8_t buffer_ ## SIZE[NBUFFERS][SIZE];

BUFFER_SIZES(MALLOC_BUFFERS);

size_t largest_malloc = 0;

namespace redmagic {
  extern thread_local bool protected_malloc;
}
using namespace redmagic;

extern "C" void *__real_malloc(size_t size);

extern "C" void *__wrap_malloc(size_t size) {

#ifdef MPROTECTED_ALLOC
  if(size < MPROTECTED_ALLOC)
    size = MPROTECTED_ALLOC;
  else {
    size += 4*1024;
    size &= ~(4*1024-1);
  }
  //assert(size < 40*1024);
  {
    uint8_t *buffer = (uint8_t*)mmap(NULL, size + 8*1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(buffer != MAP_FAILED);
    *((size_t*)buffer) = size;

    int r = mprotect(buffer, 4*1024, PROT_NONE);
    assert(!r);
    r = mprotect(buffer + 4*1024 + size, 4*1024, PROT_NONE);
    assert(!r);

    return buffer + 4*1024;
  }
#endif

  // return __real_malloc(16*1024);

  if(size > largest_malloc)
    largest_malloc = size;

  if(!protected_malloc)
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
#ifdef MPROTECTED_ALLOC
  // assert that we aren't using this memory after we free it
  int r = mprotect(ptr, MPROTECTED_ALLOC, PROT_NONE);
  assert(!r);
  return;
#endif

#define FREE_BUFFER(SIZE)                                               \
  if(ptr >= (void*)buffer_##SIZE && ptr <= (void*)((uint8_t*)buffer_##SIZE + sizeof(buffer_##SIZE))) { \
    int i = ((uint8_t*)ptr - (uint8_t*)&buffer_##SIZE) / SIZE;          \
    assert(allocated_##SIZE[i] == 1);                                   \
    allocated_##SIZE[i] = 0;                                            \
    return;                                                             \
  }

  BUFFER_SIZES(FREE_BUFFER);

  if(protected_malloc)
    printf("more wtf\n");
  __real_free(ptr);
}


extern "C" void *__real_realloc(void *ptr, size_t size);

extern "C" void *__wrap_realloc(void *ptr, size_t size) {
#ifdef MPROTECTED_ALLOC
  if(size < MPROTECTED_ALLOC)
    return ptr;
  abort();
#endif

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
