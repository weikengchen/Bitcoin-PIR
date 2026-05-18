#ifndef ALIGNED_ALLOCATOR_H
#define ALIGNED_ALLOCATOR_H

#include <cstdlib>
#include <new>
#include <cstddef>
#include <memory>

// A deleter that frees memory with std::free (for pointers allocated via aligned allocators)
template <typename T>
struct AlignedDeleter {
    void operator()(T* p) const noexcept {
        std::free(static_cast<void*>(p));
    }
};

// Factory: create a unique_ptr to an aligned array using std::aligned_alloc + std::free
// Usage: auto ptr = make_unique_aligned<uint64_t, 64>(count);
template <typename T, std::size_t Alignment>
inline std::unique_ptr<T[], AlignedDeleter<T>> make_unique_aligned(std::size_t count) {
    if (count == 0) {
        return std::unique_ptr<T[], AlignedDeleter<T>>(nullptr);
    }
    std::size_t total_size = count * sizeof(T);
    if (total_size % Alignment != 0) {
        total_size = ((total_size / Alignment) + 1) * Alignment;
    }
    void* raw = std::aligned_alloc(Alignment, total_size);
    if (!raw) {
        throw std::bad_alloc();
    }
    return std::unique_ptr<T[], AlignedDeleter<T>>(static_cast<T*>(raw));
}

#endif // ALIGNED_ALLOCATOR_H
