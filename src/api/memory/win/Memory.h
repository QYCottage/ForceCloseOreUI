#pragma once

#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "api/Macro.h"

#include <Windows.h>
#include <optional>
#include <psapi.h>

#include <iostream>

#include "api/memory/Memory.h"

uintptr_t operator"" _rva(uintptr_t rva);

namespace memory {

std::unordered_map<std::string, FuncPtr> &getSignatureCache();

uintptr_t FindSig(const char *szSignature);

template <typename T>
inline void memcpy_t(void *dst, const void *src, size_t count) {
  memcpy(dst, src, count * sizeof(T));
}

template <typename T> inline void memcpy_t(void *dst, const void *src) {
  memcpy(dst, src, sizeof(T));
}

/**
 * @brief resolve signature to function pointer
 * @param t Signature
 * @return function pointer
 */
FuncPtr resolveSignature(char const *signature);

/**
 * @brief make a region of memory writable and executable, then call the
 * callback, and finally restore the region.
 * @param ptr Pointer to the region
 * @param len Length of the region
 * @param callback Callback
 */
void modify(void *ptr, size_t len, const std::function<void()> &callback);

template <class T>
inline void modify(T &ref, std::function<void(std::remove_cvref_t<T> &)> &&f) {
  modify((void *)std::addressof(ref), sizeof(T),
         [&] { f((std::remove_cvref_t<T> &)(ref)); });
}

template <typename RTN = void, typename... Args>
constexpr auto virtualCall(void const *self, uintptr_t off,
                           Args &&...args) -> RTN {
  return (*(RTN(**)(void const *, Args &&...))(*(uintptr_t *)self + off))(
      self, std::forward<Args>(args)...);
}

template <typename RTN = void, typename... Args>
constexpr auto virtualCall(uintptr_t self, uintptr_t off,
                           Args &&...args) -> RTN {
  return (*(RTN(**)(uintptr_t, Args && ...))(*(uintptr_t *)self + off))(
      self, std::forward<Args>(args)...);
}

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

template <typename T> std::optional<T> safeDAccess(void *ptr, intptr_t off) {
  if (ptr == nullptr)
    return std::nullopt;
  return *(T *)(((uintptr_t)ptr) + (uintptr_t)off);
}

template <typename T>
std::optional<T> safeDAccess(uintptr_t ptr, intptr_t off) {
  if (ptr == 0)
    return std::nullopt;
  return *(T *)(((uintptr_t)ptr) + (uintptr_t)off);
}

template <typename T>
constexpr void destruct(void *ptr, intptr_t off) noexcept {
  std::destroy_at(
      std::launder(reinterpret_cast<T *>(((uintptr_t)ptr) + (uintptr_t)off)));
}

template <typename T, class... Types>
constexpr auto construct(void *ptr, intptr_t off, Types &&...args) {
  return std::construct_at(
      std::launder(reinterpret_cast<T *>(((uintptr_t)ptr) + (uintptr_t)off)),
      std::forward<Types>(args)...);
}

[[nodiscard]] inline size_t getMemSizeFromPtr(void *ptr) {
  if (!ptr) {
    return 0;
  }
  return _msize(ptr);
}

template <typename T, typename D>
[[nodiscard]] inline size_t getMemSizeFromPtr(std::unique_ptr<T, D> &ptr) {
  if (!ptr) {
    return 0;
  }
  return _msize(ptr.get());
}

template <template <typename> typename P, typename T>
[[nodiscard]] inline size_t getMemSizeFromPtr(P<T> &ptr)
  requires(std::derived_from<P<T>, std::_Ptr_base<T>>)
{
  auto &refc = dAccess<std::_Ref_count_base *>(std::addressof(ptr), 8);
  if (!refc) {
    return 0;
  }
  auto &rawptr = dAccess<T *>(std::addressof(ptr), 0);
  if (!rawptr) {
    return 0;
  }
  if constexpr (!std::is_array_v<T>) {
    if (rawptr == dAccess<T *>(refc, 8 + 4 * 2)) {
      return getMemSizeFromPtr(rawptr);
    }
  }
  // clang-format off
    return _msize(refc // ptr* 8, rep* 8
    ) - ( // rep:
    8 +                        // vtable
    4 * 2 +                    // uses & weaks
   (std::is_array_v<T> ? 8 : 0)// size
    /**/                       // storage
    );
  // clang-format on
}

bool IsReadableMemory(void *ptr, size_t size);

template <class R = void, class... Args>
constexpr auto addressCall(void const *address, auto &&...args) -> R {
  return ((R(*)(Args...))address)(std::forward<decltype((args))>(args)...);
}

template <class R = void, class... Args>
constexpr auto addressCall(uintptr_t address, auto &&...args) -> R {
  return ((R(*)(Args...))address)(std::forward<decltype((args))>(args)...);
}

} // namespace memory

#define CC_CALL(iname, address, Ret, ...)                                      \
  ((Ret(*)(__VA_ARGS__))(memory::resolveSignature(address)))