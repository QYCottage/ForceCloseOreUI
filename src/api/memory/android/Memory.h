#pragma once

#include "api/memory/Memory.h"
#include <cstdint>
#include <dlfcn.h>
#include <fstream>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

namespace memory {

uintptr_t resolveSignature(const char *signature);

template <typename T>
[[nodiscard]] constexpr T &dAccess(void *ptr, intptr_t off) {
  return *(T *)(((uintptr_t)ptr) + (uintptr_t)(off));
}

template <typename T>
[[nodiscard]] constexpr T &dAccess(uintptr_t ptr, intptr_t off) {
  return *(T *)(((uintptr_t)ptr) + (uintptr_t)(off));
}

template <typename T>
[[nodiscard]] constexpr T const &dAccess(void const *ptr, intptr_t off) {
  return *(T *)(((uintptr_t)ptr) + (uintptr_t)off);
}
// Overload for non-const member functions
template <typename RTN = void, typename... Args>
constexpr auto virtualCall(void *self, size_t off, Args &&...args) -> RTN {
  auto vtable = *reinterpret_cast<void ***>(self);
  auto fn = reinterpret_cast<RTN (*)(void *, Args &&...)>(vtable[off]);
  return fn(self, std::forward<Args>(args)...);
}

// Overload for const member functions
template <typename RTN = void, typename... Args>
constexpr auto virtualCall(const void *self, size_t off, Args &&...args)
    -> RTN {
  // auto vtable = *reinterpret_cast<const void ***>(self);
  auto **vtable = *(void ***)self;
  auto fn = reinterpret_cast<RTN (*)(const void *, Args &&...)>(vtable[off]);
  return fn(self, std::forward<Args>(args)...);
}

template <class R = void, class... Args>
constexpr auto addressCall(void const *address, Args &&...args) -> R {
  return ((R(*)(Args...))(address))(std::forward<Args>(args)...);
}

template <class R = void, class... Args>
constexpr auto addressCall(uintptr_t address, Args &&...args) -> R {
  return ((R(*)(Args...))(address))(std::forward<Args>(args)...);
}
} // namespace memory