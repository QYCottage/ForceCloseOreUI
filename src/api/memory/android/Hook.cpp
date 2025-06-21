#include "api/memory/Hook.h"
#include <mutex>
#include <set>
#include <type_traits>
#include <unordered_map>

#include "Memory.h"

#include "Gloss.h"

#include <android/log.h>
#include <chrono>
#include <inttypes.h>

#define LOGI(...)                                                              \
  __android_log_print(ANDROID_LOG_INFO, "LeviLogger", __VA_ARGS__)

namespace memory {

struct HookElement {
  FuncPtr detour{};
  FuncPtr *originalFunc{};
  HookPriority priority{};
  int id{};

  bool operator<(const HookElement &other) const {
    if (priority != other.priority)
      return priority < other.priority;
    return id < other.id;
  }
};

struct HookData {
  FuncPtr target{};
  FuncPtr origin{};
  FuncPtr start{};
  GHook glossHandle{};
  int hookId{};
  std::set<HookElement> hooks{};

  ~HookData() {
    if (glossHandle != nullptr) {
      GlossHookDelete(glossHandle);
    }
  }

  void updateCallList() {
    FuncPtr *last = nullptr;
    for (auto &item : this->hooks) {
      if (last == nullptr) {
        this->start = item.detour;
        last = item.originalFunc;
        *last = this->origin;
      } else {
        *last = item.detour;
        last = item.originalFunc;
      }
    }
    if (last == nullptr) {
      this->start = this->origin;
    } else {
      *last = this->origin;
    }
  }

  int incrementHookId() { return ++hookId; }
};

std::unordered_map<FuncPtr, std::shared_ptr<HookData>> &getHooks() {
  static std::unordered_map<FuncPtr, std::shared_ptr<HookData>> hooks;
  return hooks;
}

static std::mutex hooksMutex{};

int hook(FuncPtr target, FuncPtr detour, FuncPtr *originalFunc,
         HookPriority priority, bool suspendThreads) {
  static bool initialized = false;
  if (!initialized) {
    GlossInit(true);
    initialized = true;
  }

  std::lock_guard lock(hooksMutex);
  auto it = getHooks().find(target);
  if (it != getHooks().end()) {
    auto hookData = it->second;
    hookData->hooks.insert(
        {detour, originalFunc, priority, hookData->incrementHookId()});
    hookData->updateCallList();

    if (hookData->glossHandle) {
      GlossHookReplaceNewFunc(hookData->glossHandle, hookData->start);
    }
    return 0;
  }

  auto hookData = std::make_shared<HookData>();
  hookData->target = target;
  hookData->origin = target;
  hookData->start = detour;
  hookData->hooks.insert(
      {detour, originalFunc, priority, hookData->incrementHookId()});

  hookData->glossHandle = GlossHook(target, hookData->start, &hookData->origin);

  if (!hookData->glossHandle) {
    return -1;
  }

  hookData->updateCallList();
  getHooks().emplace(target, hookData);
  return 0;
}

bool unhook(FuncPtr target, FuncPtr detour, bool suspendThreads) {
  std::lock_guard lock(hooksMutex);

  if (target == nullptr) {
    return false;
  }

  auto hookDataIter = getHooks().find(target);
  if (hookDataIter == getHooks().end()) {
    return false;
  }

  auto &hookData = hookDataIter->second;
  for (auto it = hookData->hooks.begin(); it != hookData->hooks.end(); ++it) {
    if (it->detour == detour) {
      hookData->hooks.erase(it);
      hookData->updateCallList();

      if (hookData->glossHandle) {
        if (hookData->hooks.empty()) {
          GlossHookDelete(hookData->glossHandle);
          getHooks().erase(target);
        } else {
          GlossHookReplaceNewFunc(hookData->glossHandle, hookData->start);
        }
      }
      return true;
    }
  }

  return false;
}

void unhookAll() {
  std::lock_guard lock(hooksMutex);

  for (auto &[target, hookData] : getHooks()) {
    if (hookData->glossHandle) {
      GlossHookDelete(hookData->glossHandle);
    }
  }

  getHooks().clear();
}

FuncPtr resolveIdentifier(const char *identifier) {
  uintptr_t result = resolveSignature(identifier);
  if (result) {
    // LOGI("[resolveIdentifier] Resolved identifier [%s] to address 0x%lx",
    //      identifier, result);
    return reinterpret_cast<FuncPtr>(result);
  } else {
    // LOGI("[resolveIdentifier] Failed to resolve signature for [%s]",
    //     identifier);
    return nullptr;
  }
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