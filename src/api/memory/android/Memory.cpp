#pragma once
#include <android/log.h>
#include <cstdint>
#include <dlfcn.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>


#define LOG_TAG "MemoryScanner"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace memory {

// 签名结构（字节 + 是否必须匹配的掩码）
struct SigPattern {
  std::vector<uint8_t> bytes;
  std::vector<bool> mask;
};

// 获取目标模块信息
struct ModuleInfo {
  uintptr_t base = 0;
  size_t size = 0;
};

// 从 /proc/self/maps 获取 libminecraftpe.so 的起始地址和大小
static bool getLibMinecraftInfo(ModuleInfo &info) {
  std::ifstream maps("/proc/self/maps");
  if (!maps.is_open()) {
    LOGE("Failed to open /proc/self/maps");
    return false;
  }

  std::string line;
  while (std::getline(maps, line)) {
    if (line.find("libminecraftpe.so") != std::string::npos) {
      std::istringstream iss(line);
      std::string range;
      iss >> range;

      uintptr_t start = 0, end = 0;
      if (sscanf(range.c_str(), "%lx-%lx", &start, &end) == 2) {
        info.base = start;
        info.size = end - start;
        LOGI("libminecraftpe.so base=0x%lx size=%zu", info.base, info.size);
        return true;
      }
    }
  }

  LOGE("libminecraftpe.so not found in /proc/self/maps");
  return false;
}

// 解析签名字符串（例如: "48 8B ?? ?? ?? 89"）
static SigPattern parsePattern(const std::string &signature) {
  SigPattern pattern;
  for (size_t i = 0; i < signature.size();) {
    if (signature[i] == ' ') {
      ++i;
      continue;
    }

    if (signature[i] == '?') {
      pattern.bytes.push_back(0);
      pattern.mask.push_back(false);
      if (i + 1 < signature.size() && signature[i + 1] == '?')
        i += 2;
      else
        ++i;
    } else {
      if (i + 1 >= signature.size())
        break;
      char buf[3] = {signature[i], signature[i + 1], 0};
      uint8_t val = static_cast<uint8_t>(strtoul(buf, nullptr, 16));
      pattern.bytes.push_back(val);
      pattern.mask.push_back(true);
      i += 2;
    }
  }
  return pattern;
}

// 最简单的线性扫描算法
static uintptr_t scanPattern(const uint8_t *start, const uint8_t *end,
                             const SigPattern &pattern) {
  const size_t plen = pattern.bytes.size();
  if (plen == 0)
    return 0;

  for (const uint8_t *ptr = start; ptr < end - plen; ++ptr) {
    bool matched = true;
    for (size_t i = 0; i < plen; ++i) {
      if (pattern.mask[i] && ptr[i] != pattern.bytes[i]) {
        matched = false;
        break;
      }
    }
    if (matched)
      return reinterpret_cast<uintptr_t>(ptr);
  }
  return 0;
}

// 入口函数：查找签名
uintptr_t resolveSignature(const char *signature) {
  ModuleInfo mod;
  if (!getLibMinecraftInfo(mod))
    return 0;

  SigPattern pat = parsePattern(signature);
  LOGI("Scanning for signature: %s", signature);

  const uint8_t *start = reinterpret_cast<const uint8_t *>(mod.base);
  const uint8_t *end = start + mod.size;
  uintptr_t result = scanPattern(start, end, pat);

  if (result)
    LOGI("Signature found at 0x%lx", result);
  else
    LOGE("Signature not found: %s", signature);

  return result;
}

} // namespace memory