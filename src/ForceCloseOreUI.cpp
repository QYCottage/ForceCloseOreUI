#include <filesystem>
#include <fstream>
#include <functional>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <unordered_map>

#include "api/memory/Hook.h"
#include <cstdio>

namespace fs = std::filesystem;
#if __arm__
#include <unistd.h>
extern "C" int __wrap_getpagesize() { return sysconf(_SC_PAGESIZE); }

#endif

#if __arm__ || __aarch64__
#include "jni.h"
JNIEnv *env = nullptr;

jobject getGlobalContext(JNIEnv *env) {
  jclass activity_thread = env->FindClass("android/app/ActivityThread");
  jmethodID current_activity_thread =
      env->GetStaticMethodID(activity_thread, "currentActivityThread",
                             "()Landroid/app/ActivityThread;");
  jobject at =
      env->CallStaticObjectMethod(activity_thread, current_activity_thread);
  jmethodID get_application = env->GetMethodID(
      activity_thread, "getApplication", "()Landroid/app/Application;");
  jobject context = env->CallObjectMethod(at, get_application);
  if (env->ExceptionCheck())
    env->ExceptionClear();
  return context;
}

std::string getAbsolutePath(JNIEnv *env, jobject file) {
  jclass file_class = env->GetObjectClass(file);
  jmethodID get_abs_path =
      env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;");
  auto jstr = (jstring)env->CallObjectMethod(file, get_abs_path);
  if (env->ExceptionCheck())
    env->ExceptionClear();
  const char *cstr = env->GetStringUTFChars(jstr, nullptr);
  std::string result(cstr);
  env->ReleaseStringUTFChars(jstr, cstr);
  return result;
}

std::string getPackageName(JNIEnv *env, jobject context) {
  jclass context_class = env->GetObjectClass(context);
  jmethodID get_pkg_name =
      env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
  auto jstr = (jstring)env->CallObjectMethod(context, get_pkg_name);
  if (env->ExceptionCheck())
    env->ExceptionClear();
  const char *cstr = env->GetStringUTFChars(jstr, nullptr);
  std::string result(cstr);
  env->ReleaseStringUTFChars(jstr, cstr);
  return result;
}

std::string getInternalStoragePath(JNIEnv *env) {
  jclass env_class = env->FindClass("android/os/Environment");
  jmethodID get_storage_dir = env->GetStaticMethodID(
      env_class, "getExternalStorageDirectory", "()Ljava/io/File;");
  jobject storage_dir = env->CallStaticObjectMethod(env_class, get_storage_dir);
  return getAbsolutePath(env, storage_dir);
}

std::string GetModsFilesPath(JNIEnv *env) {
  jobject app_context = getGlobalContext(env);
  if (!app_context) {
    return "";
  }
  auto package_name = getPackageName(env, app_context);
  for (auto &c : package_name)
    c = tolower(c);

  return (fs::path(getInternalStoragePath(env)) / "Android" / "data" /
          package_name / "mods");
}

SKY_AUTO_STATIC_HOOK(
    Hook1, memory::HookPriority::Normal,
    std::initializer_list<const char *>(
        {"? ? ? D1 ? ? ? A9 ? ? ? 91 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? "
         "A9 ? ? ? D5 ? ? ? F9 ? ? ? F8 ? ? ? 39 ? ? ? 34 ? ? ? 12"}),
    int, void *_this, JavaVM *vm) {

  vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_4);
  return origin(_this, vm);
}

#endif

class OreUIConfig {
public:
  void *mUnknown1;
  void *mUnknown2;
  std::function<bool()> mUnknown3;
  std::function<bool()> mUnknown4;
};

class OreUi {
public:
  std::unordered_map<std::string, OreUIConfig> mConfigs;
};

// clang-format off
#if __arm__
#define OREUI_PATTERN 
   {""}

#elif __aarch64__
#define OREUI_PATTERN                                                                     \
     std::initializer_list<const char *>({                                                \
    "? ? ? D1 ? ? ? A9 ? ? ? 91 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 E8 03 03 AA" \
  })
#define OREUI_registerToggle                                                                                                  \
     std::initializer_list<const char *>({                                                                               \
    "? ? ? D1 ? ? ? A9 ? ? ? 91 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? D5 F7 03 00 AA ? ? ? F9 F4 03 03 AA F3 03 00 AA"    \
  })                                                                                                                     \

  #define OREUI_getBool                                                                                               \
     std::initializer_list<const char *>({                                                                               \
    "? ? ? F9 ? ? ? F9 ? ? ? B4 E0 03 08 AA ? ? ? F9 ? ? ? F9 ? ? ? B5 ? ? ? 39"    \
  })                                                                                                                     \

#elif _WIN32
#define OREUI_PATTERN                                                                                                    \
     std::initializer_list<const char *>({                                                                               \
    "40 53 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 78 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 49 8B E9 4C 89 44 24"    \
  })                                                                                                                     \

#define OREUI_registerToggle                                                                                                  \
     std::initializer_list<const char *>({                                                                               \
    "89 54 24 ? 53 55 56 57 41 54 41 56 41 57 48 83 EC 60 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 49 8B F1"    \
  })                                                                                                                     \

  #define OREUI_getBool                                                                                               \
     std::initializer_list<const char *>({                                                                               \
    "48 8B 41 ? 48 8B 90 ? ? ? ? 48 85 D2 74 ? 48 8B 4A"    \
  })                                                                                                                     \


 #endif

// clang-format on

namespace {

#if defined(_WIN32)

std::string getLocalAppDataPath() {
  char path[260];
  size_t len;
  getenv_s(&len, path, sizeof(path), "LOCALAPPDATA");
  if (len > 0) {
    return std::string(path);
  }
  char userProfile[260];
  getenv_s(&len, userProfile, sizeof(userProfile), "USERPROFILE");
  if (len > 0) {
    return std::string(userProfile) + "\\AppData\\Local";
  }
  return ".";
}

std::string getUWPModsDir() {
  std::string appDataPath = getLocalAppDataPath();
  std::string uwpMods = appDataPath + "\\mods\\ForceCloseOreUI\\";
  return uwpMods;
}
#endif

bool testDirWritable(const std::string &dir) {
  std::error_code _;
  std::filesystem::create_directories(dir, _);
  std::string testFile = dir + "._perm_test";
  std::ofstream ofs(testFile);
  bool ok = ofs.is_open();
  ofs.close();
  if (ok)
    std::filesystem::remove(testFile, _);
  return ok;
}

std::string getConfigDir() {
#if defined(_WIN32)
  std::string primary = "mods/ForceCloseOreUI/";
  if (testDirWritable(primary))
    return primary;
  std::string fallback = getUWPModsDir();
  if (testDirWritable(fallback))
    return fallback;
  return primary;
#else
  std::string primary = "/storage/emulated/0/games";
  if (!primary.empty()) {
    primary += "/ForceCloseOreUI/";
    if (testDirWritable(primary))
      return primary;
  }
  if (!env)
    return primary;
  std::string base = GetModsFilesPath(env);
  if (!base.empty()) {
    base += "/ForceCloseOreUI/";
    if (testDirWritable(base))
      return base;
  }
  return primary;
#endif
}

nlohmann::json outputJson;
std::string dirPath = "";
std::string filePath = dirPath + "config.json";

SKY_AUTO_STATIC_HOOK(Hook2, memory::HookPriority::Normal, OREUI_PATTERN, void,
                     void *a1, void *a2, void *a3, void *a4, void *a5, void *a6,
                     void *a7, void *a8, void *a9, void *a10, OreUi &a11,
                     void *a12) {

  dirPath = getConfigDir();
  filePath = dirPath + "config.json";
  if (!std::filesystem::exists(filePath)) {
    for (auto &data : a11.mConfigs) {
      outputJson[data.first] = false;
    }
    std::filesystem::create_directories(dirPath);
    std::ofstream outFile(filePath);
    outFile << outputJson.dump(4);
    outFile.close();
  } else {
    std::ifstream inFile(filePath);
    inFile >> outputJson;
    inFile.close();
  }

  for (auto &data : a11.mConfigs) {
    bool value = false;
    if (outputJson.contains(data.first) &&
        outputJson[data.first].is_boolean()) {
      value = outputJson[data.first];
    }
    data.second.mUnknown3 = [value]() { return value; };
    data.second.mUnknown4 = [value]() { return value; };
  }
  origin(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
}

std::map<void *, std::string> mHooks;

SKY_AUTO_STATIC_HOOK(Hook4, memory::HookPriority::Normal, OREUI_registerToggle,
                     void, void *a1, int toggleId, void **option,
                     const std::string *tagId, void *a5) {

  mHooks[*option] = *tagId;
  origin(a1, toggleId, option, tagId, a5);
}

SKY_AUTO_STATIC_HOOK(Hook5, memory::HookPriority::Normal,
                     "48 8B 41 ? 48 8B 90 ? ? ? ? 48 85 D2 74 ? 48 8B 4A", bool,
                     void *a1) {
  if (mHooks.count(a1)) {
    if (mHooks[a1] == "mc-new-disconnect-screen" ||
        mHooks[a1] == "mc-cloud-file-upload" ||
        mHooks[a1] == "mc-enable-new-player-permissions-screen" ||
        mHooks[a1] == "mc-enable-new-trial-mode") {
      *(bool *)((uintptr_t)a1 + 0x10) = false;
      *(bool *)((uintptr_t)a1 + 0x11) = false;
    }
    return origin(a1);
  }
}

} // namespace
