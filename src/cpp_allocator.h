#ifndef REDMAGIC_CPP_ALLOCATOR_H_
#define REDMAGIC_CPP_ALLOCATOR_H_

#include <memory>
#include <cstdlib>

extern "C" void *__real_malloc(size_t size);
extern "C" void __real_free(void *ptr);

namespace redmagic {
  template <typename T>
  class RealMallocAllocator {
  public:
    typedef T                 value_type;
    typedef value_type*       pointer;
    typedef const value_type* const_pointer;
    typedef value_type&       reference;
    typedef const value_type& const_reference;
    typedef std::size_t       size_type;
    typedef std::ptrdiff_t    difference_type;

    template <typename U>
    struct rebind { typedef RealMallocAllocator<U> other; };

    RealMallocAllocator() noexcept {}
    template <typename U> RealMallocAllocator(const RealMallocAllocator<U> &x) noexcept {}
    ~RealMallocAllocator() noexcept {}

    pointer address(reference x) const { return &x; }
    const_pointer address(const_reference x) const {
      return x;
    }

    pointer allocate(size_type n, const_pointer hint = 0) {
      void* p = __real_malloc(n * sizeof(T));
      if (!p) {
#ifdef __EXCEPTIONS
        throw std::bad_alloc();
#else
        std::abort();
#endif
      }
      return static_cast<pointer>(p);
    }

    void deallocate(pointer p, size_type n = 0) {
      __real_free(p);
    }

    size_type max_size() const {
      return static_cast<size_type>(-1) / sizeof(T);
    }

    template<typename U, typename... Args>
    void construct(U* p, Args&&... x) {
      new(p) U(std::forward<Args>(x)...);
    }

    template <typename U>
    void destroy(U *p) { p->~U(); }

  private:
    void operator=(const RealMallocAllocator&);
  };

  template<typename A, typename B>
  inline bool operator==(const RealMallocAllocator<A>&, const RealMallocAllocator<B>&) {
    return true;
  }

  template<typename A, typename B>
  inline bool operator!=(const RealMallocAllocator<A>&, const RealMallocAllocator<B>&) {
    return false;
  }

}


#endif // REDMAGIC_CPP_ALLOCATOR_H_
