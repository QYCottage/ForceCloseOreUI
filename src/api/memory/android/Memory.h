#pragma once

#include "Gloss.h"
#include "api/memory/Memory.h"
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace memory {

struct SigPattern {
  std::vector<uint8_t> pattern;
  std::vector<bool> mask;
};

inline std::vector<size_t> buildBMHTable(const SigPattern &sigpat) {
  std::vector<size_t> table(256, sigpat.pattern.size());
  for (size_t i = 0; i + 1 < sigpat.pattern.size(); ++i) {
    if (sigpat.mask[i]) {
      table[sigpat.pattern[i]] = sigpat.pattern.size() - 1 - i;
    }
  }
  return table;
}

inline const uint8_t *bmSearch(const uint8_t *base, const uint8_t *end,
                               const SigPattern &sigpat,
                               const std::vector<size_t> &bmhTable) {
  const size_t len = sigpat.pattern.size();
  for (const uint8_t *pos = base; pos <= end;) {
    size_t i = len - 1;
    while (i < len && (!sigpat.mask[i] || pos[i] == sigpat.pattern[i])) {
      if (i == 0)
        return pos;
      --i;
    }
    size_t skip = 1;
    if (sigpat.mask[len - 1])
      skip = bmhTable[pos[len - 1]];
    pos += skip;
  }
  return nullptr;
}

inline const uint8_t *maskScan(const uint8_t *start, const uint8_t *end,
                               const SigPattern &pat) {
  for (const uint8_t *ptr = start; ptr <= end; ++ptr) {
    bool found = true;
    for (size_t i = 0; i < pat.pattern.size(); ++i) {
      if (pat.mask[i] && ptr[i] != pat.pattern[i]) {
        found = false;
        break;
      }
    }
    if (found)
      return ptr;
  }
  return nullptr;
}

inline uintptr_t resolveSignature(const std::string &signature) {
  static std::unordered_map<std::string, uintptr_t> sigCache;
  static std::unordered_map<std::string,
                            std::pair<SigPattern, std::vector<size_t>>>
      patternCache;
  static std::mutex cacheMutex;

  static bool initialized = false;
  static uintptr_t moduleBase = 0;
  static size_t moduleSize = 0;
  static GHandle handle = 0;

  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    auto it = sigCache.find(signature);
    if (it != sigCache.end())
      return it->second;
  }

  if (!initialized) {
    GlossInit(true);
    handle = GlossOpen("libminecraftpe.so");
    moduleBase = GlossGetLibBiasEx(handle);
    moduleSize = GlossGetLibFileSize(handle);
    initialized = true;
  }

  uintptr_t addr = GlossSymbol(handle, signature.c_str(), nullptr);
  if (addr) {
    std::lock_guard<std::mutex> lock(cacheMutex);
    sigCache[signature] = addr;
    return addr;
  }

  SigPattern sigpat;
  std::vector<size_t> bmhTable;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    auto it = patternCache.find(signature);
    if (it != patternCache.end()) {
      sigpat = it->second.first;
      bmhTable = it->second.second;
    } else {
      for (size_t i = 0; i < signature.size();) {
        if (signature[i] == ' ') {
          ++i;
          continue;
        }
        if (signature[i] == '?') {
          sigpat.pattern.push_back(0);
          sigpat.mask.push_back(false);
          i += (i + 1 < signature.size() && signature[i + 1] == '?') ? 2 : 1;
        } else {
          if (i + 1 >= signature.size())
            break;
          char buf[3] = {signature[i], signature[i + 1], 0};
          unsigned long value = strtoul(buf, nullptr, 16);
          sigpat.pattern.push_back(static_cast<uint8_t>(value));
          sigpat.mask.push_back(true);
          i += 2;
        }
      }
      bmhTable = buildBMHTable(sigpat);
      patternCache[signature] = {sigpat, bmhTable};
    }
  }
  if (sigpat.pattern.empty())
    return moduleBase;

  const uint8_t *start = reinterpret_cast<const uint8_t *>(moduleBase);
  const uint8_t *end = start + moduleSize - sigpat.pattern.size();

  uintptr_t result = 0;
  const uint8_t *found_ptr = nullptr;
  found_ptr = bmSearch(start, end, sigpat, bmhTable);
  if (!found_ptr)
    found_ptr = maskScan(start, end, sigpat);
  if (found_ptr)
    result = reinterpret_cast<uintptr_t>(found_ptr);
  else
    result = 0;

  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    sigCache[signature] = result;
  }
  return result;
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