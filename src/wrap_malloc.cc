#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <new>

// we can't direclty use allocators when we are tracing since it might screw with their internal states

#define NBUFFERS 8
#define BUFFERS_SIZE (8*1024)

__thread uint8_t allocated[NBUFFERS];
__thread uint8_t buffer[NBUFFERS][BUFFERS_SIZE];
size_t largest_malloc = 0;

extern "C" void *__real_malloc(size_t size);

extern "C" void *__wrap_malloc(size_t size) {
  if(size > largest_malloc)
    largest_malloc = size;

  if(size > BUFFERS_SIZE)
    goto use_real_malloc;

  for(int i = 0; i < NBUFFERS; i++) {
    if(allocated[i] == 0) {
      allocated[i] = 1;
      return buffer[i];
    }
  }

 use_real_malloc:
  printf("============trying to use real malloc\n");
  abort();

  return __real_malloc(size);
}

extern "C" void __real_free(void *ptr);

extern "C" void __wrap_free(void *ptr) {
  if(ptr >= (void*)buffer && ptr <= (void*)(buffer + sizeof(buffer))) {
    // find the buffer and set it to unallocated
    int i = ((uint8_t*)ptr - (uint8_t*)&buffer) / BUFFERS_SIZE;
    assert(allocated[i] == 1);
    allocated[i] = 0;
  } else {
    printf("more wtf\n");
    __real_free(ptr);
  }
}


extern "C" void *__real_realloc(void *ptr, size_t size);

extern "C" void *__wrap_realloc(void *ptr, size_t size) {
  if(size > largest_malloc)
    largest_malloc = size;
  if(ptr >= (void*)buffer && ptr <= (void*)(buffer + sizeof(buffer))) {
    if(size < BUFFERS_SIZE)
      return ptr;
    abort();
  } else {
    return __real_realloc(ptr, size);
  }
}

extern "C" void *__real_calloc(size_t mnemb, size_t size);

extern "C" void *__wrap_calloc(size_t mnemb, size_t size) {
  // TODO:?
  // isn't used by asmjit
  abort();
  return __real_calloc(mnemb, size);
}
