#include "api/memory/Hook.h"
#include <mutex>
#include <set>
#include <type_traits>
#include <unordered_map>

#include "Memory.h"

#include <android/log.h>
#include <chrono>
#include <inttypes.h>

#include "pl/Hook.h"
#include "pl/Signature.h"

#define LOGI(...)                                                              \
  __android_log_print(ANDROID_LOG_INFO, "LeviLogger", __VA_ARGS__)

namespace memory {

int hook(FuncPtr target, FuncPtr detour, FuncPtr *originalFunc,
         HookPriority priority, bool) {
  return pl::hook::pl_hook(target, detour, originalFunc,
                           pl::hook::Priority(priority));
}

bool unhook(FuncPtr target, FuncPtr detour, bool) {
  return pl::hook::pl_unhook(target, detour);
}

FuncPtr resolveIdentifier(char const *identifier) {
  return reinterpret_cast<FuncPtr>(pl::signature::resolveSignature(identifier));
}

FuncPtr resolveIdentifier(std::initializer_list<const char *> identifiers) {
  for (const auto &identifier : identifiers) {
    FuncPtr result = resolveIdentifier(identifier);
    if (result != nullptr) {
      return result;
    }
  }
  return nullptr;
}

} // namespace memory