#ifndef GLOSSHOOK_H
#define GLOSSHOOK_H

#ifndef __ANDROID__
#error GlossHook only support android
#else
#if !(defined __arm__) && !(defined __aarch64__)
#error GlossHook only support arm and arm64
#endif
#endif

#if (defined __clang__) || (defined __GNUC__)
#define GLOSS_API __attribute__((visibility("default")))
#else
#define GLOSS_API
#endif

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h> 

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __arm__
#define GET_INST_SET(addr) (addr & 1 ? i_set::I_THUMB : i_set::I_ARM) // check addr is arm or thumb (arm: addr thumb: addr + 1)
#endif 

	typedef enum { I_NONE = 0, I_THUMB, I_ARM, I_ARM64 } i_set; // inst mode

	typedef void* GHandle; // library handle

	typedef void* GHook; // hook handle

	typedef struct PermissionFlags // memory permission
	{
		bool bRead : 1;
		bool bWrite : 1;
		bool bExecute : 1;
		bool bPrivate : 1;
		bool bShared : 1;
		bool align : 3;
	} p_flag;

	// register patch
	typedef struct GlossRegister
	{
		// pc register cannot be changed, only read
		// x18 register is occupied by a jump instruction, cannot be changed
#ifdef __arm__
		enum e_reg { R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, FP = R11, R12, IP = R12, R13, SP = R13, R14, LR = R14, R15, PC = R15, CPSR, MAX_REG };

		union {
			uint32_t r[MAX_REG];
			struct { uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc, cpsr; } regs;
		};
#elif __aarch64__
		enum e_reg {
			X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, FP = X29,
			X30, LR = X30, X31, SP = X31, PC, CPSR, MAX_REG,
			Q0 = X0, Q1 = X1, Q2 = X2, Q3 = X3, Q4 = X4, Q5 = X5, Q6 = X6, Q7 = X7, Q8 = X8, Q9 = X9, Q10 = X10, Q11 = X11, Q12 = X12, Q13 = X13, Q14 = X14, Q15 = X15,
			Q16 = X16, Q17 = X17, Q18 = X18, Q19 = X19, Q20 = X20, Q21 = X21, Q22 = X22, Q23 = X23, Q24 = X24, Q25 = X25, Q26 = X26, Q27 = X27, Q28 = X28, Q29 = X29, Q30 = X30, Q31 = X31,
			MAX_Q_REG
		};

		typedef union {
			__uint128_t q;
			double d[2];
			float f[4];
		} __qreg;

		typedef union {
			uint64_t x;
			uint32_t w[2];
		} __xreg;

		union {
			struct {
				__uint128_t q[MAX_Q_REG];
				uint64_t x[MAX_REG];
			} r;

			struct {
				__qreg q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15, q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31;
				__xreg x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
				__xreg lr, sp; uint64_t pc, cpsr;
			} regs;
		};
#endif 
	} gloss_reg;

	// Enable/Disable GlossHook log
	// Default: false (disable)
	// Tag: GlossHook
	GLOSS_API void GlossSetLog(bool enable);

	// ******************************************************* Library API ******************************************************************************
	//	
	// Gloss library module api uses xdl library to implement, 
	// because the dl library provided by the linker (dl) series functions have some problems. (such as Android 7.0+ linker namespace)
	// More see: https://github.com/hexhacking/xDL (MIT License)
	// 
	// About { load_bias }:
	// { load_bias } is the starting address of the executable file or dynamic shared library in memory.
	// { load_bias } has many names, such as: OffsetAddr, BaseAddr, LoadBase, ImageBase, etc.
	// { load_bias } is a naming convention used by Google Android source code, We use this naming convention here. (or abbreviated as bias)
	// { load_bias } is not the address of the first loaded program header of the dynamic library.
	// According to the Android source code, the initial address at which the dynamic library is first loaded into memory is defined as: { load_start }.
	// { load_start } and { load_bias } are different only in Android 8.0 and above.
	// For Android 7.0 and below, { load_bias } and { load_start } are the same.
	// For Android 8.0 and above, if a dynamic library (elf) has a program header (segment) of type PT_LOAD with a p_paddr field of 0, 
	// then { load_bias } and { load_start } are the same,
	// otherwise, { load_bias } and { load_start } are not equal, for example, the arm64 version of { libart.so } in Android 8.0/9.0.
	// Since most methods to obtain { load_bias } do not handle and distinguish { load_bias } and { load_start }, 
	// so using them to obtain { load_bias } will get the wrong { load_bias }.
	// Therefore, it is recommended to use GlossAPI or use xdl library to obtain { load_bias }.
	// 

	/*
	* GlossFindLibMapping - Find the memory mapping info of the library in the process. (proc/{pid}/maps or /proc/self/maps)
	*
	* @param lib_name - The library name (or path name) to find. (Cannot use NULL)
	* @param pid - The process id to search. (-1 for current process, pid_t for other process)
	* @param lib_path - The library path to store. (Can be NULL)
	* @param lib_mem_len - The library memory length to store. (Can be NULL)
	* @return The memory mapping address (load_bias) of the library. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossFindLibMapping(const char* lib_name, pid_t pid, char* lib_path, size_t* lib_mem_len);

	/*
	* GlossOpen - Open the library and get the handle. (use xdl)
	*
	* @note: It is similar to { dlopen }. But the handle returned by GlossOpen cannot be closed using { dlclose }.
	* If the library has not been loaded into memory, GlossOpen will call { dlopen } to load the library, and then call xdl_open to open the library.
	* I recommend using GlossOpen in most cases. If the library is first loaded and  GlossOpen fails, you can use { dlopen } to load the library.
	*
	* @param lib_name - The library name (or path name) to open. (Cannot use NULL)
	* @return The handle of the library. (failed: NULL)
	*/
	GLOSS_API GHandle GlossOpen(const char* lib_name);

	/*
	* GlossClose - Close the library and release the handle, from GlossOpen. (use xdl)
	*
	* @note: It is similar to { dlclose }. But the handle returned by { dlopen } cannot be closed using GlossClose.
	* If GlossOpen uses { dlopen } to load the library, set is_dlclose to true to call { dlclose } to close the library.
	* You can check the logs of GlossOpen to see if it uses { dlopen } to load the library.
	*
	* @param handle - The handle of the library to close. (Cannot use NULL)
	* @param is_dlclose - Whether to use dlclose to close the library. (default: false, use dlclose: true)
	* @return 0 if success, -1 if failed. (or return value of dlclose)
	*/
	GLOSS_API int GlossClose(GHandle handle, bool is_dlclose);

	/*
	* GlossGetLibBias - Get the load_bias of the library in the process. (use xdl)
	*
	* @param lib_name - The library name (or path name) to find. (Cannot use NULL)
	* @return The memory mapping address (load_bias) of the library. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossGetLibBias(const char* lib_name);

	/*
	* GlossGetLibBiasEx - Get the load_bias of the library in the process. (use xdl)
	*
	* @param handle - The handle (GlossOpen) of the library to get the load_bias. (Cannot use NULL)
	* @return The memory mapping address (load_bias) of the library. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossGetLibBiasEx(GHandle handle);

	/*
	* GlossGetLibPath - Get the path of the library in the process. (use xdl)
	*
	* @param handle - The handle (GlossOpen) of the library to get the path. (Cannot use NULL)
	* @return The library path of the library. (failed: NULL)
	*/
	GLOSS_API const char* GlossGetLibPath(GHandle handle);

	/*
	* GlossGetLibPathEx - Find the dynamic library in which the address is located and get the library path. (use xdl)
	*
	* @param lib_addr - The address to get the path. (Cannot use 0)
	* @param path - The library path to store. (Cannot use NULL)
	* @return True if success, false if failed.
	*/
	GLOSS_API bool GlossGetLibPathEx(uintptr_t lib_addr, char* path);

	/*
	* GlossGetLibFileSize - Get the file size of the library. (use xdl)
	*
	* @param handle - The handle (GlossOpen) of the library to get the file size. (Cannot use NULL)
	* @return The file size of the library. (failed: 0)
	*/
	GLOSS_API size_t GlossGetLibFileSize(GHandle handle);

	/*
	* GlossSymbol - find the symbol address or symbol szie (function code bytes) in the library. (use xdl)
	*
	* @note: This function is similar to { dlsym }, but it can query "debuging symbols" and obtain the function size (in bytes) at the symbol address.
	* GlossSymbol first tries to find "dynamic link symbols" (dlsym), if not found, it will try to find "debuging symbols".
	*
	* @param handle - The handle (GlossOpen) of the library to find the symbol. (Cannot use NULL)
	* @param symbol - The symbol name to find. (Cannot use NULL)
	* @param sym_size - The symbol (function) memory size to store. (can be NULL)
	* @return The symbol address. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossSymbol(GHandle handle, const char* symbol, size_t* sym_size);

	/*
	* GlossSymbolEx - Find the dynamic library in which the address is located and find the symbol address or symbol size (function code bytes). (use xdl)
	*
	* @note: see GlossSymbol.
	*
	* @param lib_addr - The address to find the symbol. (Cannot use 0)
	* @param symbol - The symbol name to find. (Cannot use NULL)
	* @param sym_size - The symbol (function) memory size to store. (can be NULL)
	* @return The symbol address. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossSymbolEx(uintptr_t lib_addr, const char* symbol, size_t* sym_size);

	/*
	* GlossGot - Get the GOT address of the symbol. (use xdl)
	*
	* @note: This function is used to obtain the GOT address of the symbol.
	*
	* @param handle - The handle (GlossOpen) of the library to find the GOT address. (Cannot use NULL)
	* @param symbol - The symbol name to find. (Cannot use NULL)
	* @param addr_list - The GOT address list to store. (Cannot use NULL) (Need to manually free memory, e.g. free(addr_list))
	* @param addr_list_size - The GOT address list size to store. (Cannot use NULL)
	* @return True if success, false if failed.
	*/
	GLOSS_API bool GlossGot(GHandle handle, const char* symbol, uintptr_t** addr_list, size_t* addr_list_size);

	/*
	* GlossAddr - Find symbol information of the address, including symbol name, size, and func address. (use xdl)
	*
	* @note: This function is similar to { dladdr }, Find which function the address is located in, and get the function name and size.
	*
	* @param lib_addr - The address to find the symbol. (Cannot use 0)
	* @param sym_addr - The symbol address to store. (Can be NULL)
	* @param sym_size - The symbol size (function code bytes) to store. (Can be NULL)
	* @param sym_name - The symbol name to store. (Can be NULL)
	* @return True if success, false if failed.
	*/
	GLOSS_API bool GlossAddr(uintptr_t lib_addr, uintptr_t* sym_addr, size_t* sym_size, char* sym_name);

	/*
	* GlossGetLibEntry - Get the entry point (.text section start address) of the library.
	*
	* @param handle - The handle (GlossOpen) of the library to get the entry point. (Cannot use NULL)
	* @return The entry address of the library. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossGetLibEntry(GHandle handle);

	/*
	* GlossGetLibSection - Get the section address and size of the library.
	*
	* @note: Libraries must be loaded into memory.
	*
	* @param lib_name - The library name (or path name) to find. (Cannot use NULL)
	* @param sec_name - The section name to find. (Can use NULL, default: ".text") (e.g. ".text", ".data", ".bss")
	* @param sec_size - The section size to store. (Can be NULL)
	* @return The section address. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossGetLibSection(const char* lib_name, const char* sec_name, size_t* sec_size);

	/*
	* GlossGetLibSegment - Get the segment (phdr) address and size of the library.
	*
	* @note: Libraries must be loaded into memory.
	*
	* @param lib_name - The library name (or path name) to find. (Cannot use NULL)
	* @param seg_id - The segment id to find. (0 for the first segment, 1 for the second segment, etc.)
	* @param seg_type - The segment type to store. (Can be NULL) (e.g. PT_LOAD, PT_DYNAMIC, PT_TLS #include <elf.h>)
	* @param seg_size - The segment size to store. (Can be NULL)
	* @return The segment address. (failed: 0)
	*/
	GLOSS_API uintptr_t GlossGetLibSegment(const char* lib_name, uint16_t seg_id, uint32_t* seg_type, size_t* seg_size);


	// ******************************************************* Memory operation API **************************************************************************
	//
	/*
	* SetMemoryPermission - Set the memory permission of the address.
	*
	* @param addr - The address to set the permission. (Cannot use 0)
	* @param len - The length of the memory to set the permission. (Cannot use 0)
	* @param type - The permission type to set, see p_flag. (Can be NULL, default: { bRead:true, bWrite:true, bExecute:true } )
	* @return True if success, false if failed.
	*/
	GLOSS_API bool SetMemoryPermission(uintptr_t addr, size_t len, p_flag* type);
	/*
	* Unprotect - Just set the memory permission to { bRead:true, bWrite:true, bExecute:true }
	* see SetMemoryPermission.
	*/
	inline bool Unprotect(uintptr_t addr, size_t len)
	{
		return SetMemoryPermission(addr, len, NULL);
	}

	/*
	* GetMemoryPermission - Get the memory permission of the address. (proc/pid/maps or /proc/self/maps)
	*
	* @param addr - The address to get the permission. (Cannot use 0)
	* @param type - The permission type to store, see p_flag. (Cannot use NULL)
	* @param pid - The process id to get the permission. (-1 for current process, pid_t for other process)
	* @param lib_name - The library name (path name) to get the permission. (can be NULL)
	* @return True if success, false if failed.
	*/
	GLOSS_API bool GetMemoryPermission(uintptr_t addr, p_flag* type, pid_t pid, const char* lib_name);
	/*
	* IsAddrExecute - Check if the address is executable.
	* see GetMemoryPermission.
	*/
	inline bool IsAddrExecute(uintptr_t addr)
	{
		p_flag type = { 0,0,0,0,0 };
		GetMemoryPermission(addr, &type, -1, NULL);
		return type.bExecute;
	}

	/*
	* WriteMemory - Write data to the address. (atomic write)
	*
	* @param addr - The address to write the data. (Cannot use NULL)
	* @param data - The data to write. (Cannot use NULL)
	* @param size - The size of the data to write. (Cannot use 0)
	* @param vp - Whether to use virtual protect to change the memory permission before writing the data. (true: unprotect, false: protect)
	*/
	GLOSS_API void WriteMemory(void* addr, void* data, size_t size, bool vp);

	/*
	* ReadMemory - Read data from the address. (atomic read)
	*
	* @param addr - The address to read the data. (Cannot use NULL)
	* @param data - The data to store. (Can be NULL)
	* @param size - The size of the data to read. (Cannot use 0)
	* @param vp - Whether to use virtual protect to change the memory permission before reading the data. (true: unprotect, false: protect)
	* @return The data read. (if data is NULL, return malloc allocated data, need to free it by yourself)
	*/
	GLOSS_API void* ReadMemory(void* addr, void* data, size_t size, bool vp);

	/*
	* MemoryFill - Fill the memory with the value.
	*
	* @param addr - The address to fill the memory. (Cannot use NULL)
	* @param value - The value to fill.
	* @param size - The size of the memory to fill. (Cannot use 0)
	* @param vp - Whether to use virtual protect to change the memory permission before filling the memory. (true: unprotect, false: protect)
	*/
	GLOSS_API void MemoryFill(void* addr, uint8_t value, size_t size, bool vp);


	// ******************************************************* Hook API ********************************************************************************
	//
	/*
	* GlossInit - Initialize the GlossHook library, Can be re-initialized multiple times.
	*
	* @param is_init_linker - Whether to initialize the linker. (AutoEnabled(Default): false)
	*/
	GLOSS_API void GlossInit(bool is_init_linker);
	// 
	// GlossHook some notes:
	// 
	// 1. About { GlossInit }
	// { GlossHook } needs to call the { GlossInit } function once at program startup, which is usually called automatically.
	// If the parameter is false, it will allocate some memory. This is necessary; otherwise, GlossHook will not function.
	// If the parameter is true, it will additionally initialize the linker functionality, obtain linker symbols, and hook linker functions.
	// Can be initialized multiple times, but only the first time is effective.
	// In some scenarios, you can manually call it to make your hook effective.
	// For example code:
	// 
	// __attribute__((constructor)) void my_entry_func()
	// {
	//     GlossInit(true); // call GlossInit at program startup
	//     
	//     // your code here
	// }
	// 
	// { GlossHook } automatic initialization occurs in the constructor attribute function,
	// If you use { GlossHook } in the constructor attribute function, you need to call GlossInit to pre-initialize.
	// (The constructor attribute function is called in a random order.)
	// 
	//  
	// 2. About { new_func } and { old_func }
	// Taking the function { GlossHook } as an example, { new_func } is the new function after being hooked, 
	// and { old_func } is the old function before being hooked.
	// { new_func } is also known as { my_func, hook_func, proxy_func, inject_func }.
	// { old_func } is also known as { prev_func, call_func }, but it is not { orig_func }, because it may be a hooked function, not the original function.
	// ( Only the first time hooking, { old_func } is { orig_func } )
	// 
	// Hook { malloc } example code:
	// 
	// void* (*old_malloc)(size_t size) = nullptr; // old_func to store
	// void* my_malloc(size_t size)      // new_func
	// {
	//     // your code here
	// 
	//     return old_malloc(size);      // call old_func
	// }
	// 
	// GlossHook((void*)malloc, (void*)my_malloc, (void**)&old_malloc); // hook malloc
	// 
	// 
	// 3. About re-entry problem of hook function
	// As an example, let's consider the hook function of malloc, If my_malloc(new_func) calls malloc again, my_malloc will enter a loop and cause a crash.
	// In addition, if my_malloc calls other functions that call malloc, it will also cause a re-entry.
	// The re-entry problem can be difficult to locate, because the cause of the crash is random, 
	// and it may be a memory access error or a function call stack overflow.
	// When the re-entry occurs in a very large function call chain, it is difficult to locate the specific position.
	// Crash code:
	//
	// void* (*old_malloc)(size_t size); // old_func to store
	// void* my_malloc(size_t size)      // new_func
	// {
	//     // your code here
	// 
	//     void* p = malloc(size);      // call malloc, my_malloc will be re-entered, and cause crash
	// 
	//     // your code here
	// 
	//     strdup("test");             // strdup call malloc, my_malloc will be re-entered, and cause crash
	// 
	//     // your code here
	// 
	//     return old_malloc(size);    // call old_func, It will not re-enter because it is the old function returned by the hook
	// }
	// 
	// GlossHook((void*)malloc, (void*)my_malloc, (void**)&old_malloc); // hook malloc
	// 
	// To avoid re-entry, it is recommended to avoid calling functions that may cause re-entry.
	// In some scenarios, we may have to use re-entry functions, and to solve this problem, we can add some additional code:
	// 
	// #include <pthread.h>
	// 
	// static pthread_key_t in_hook_key;
	// 
	// void* (*old_malloc)(size_t size);  // old_func to store
	// void* my_malloc(size_t size)       // new_func
	// {
	//    void* flag = pthread_getspecific(in_hook_key); // check if in hook
	//    if (flag == nullptr)
	//    {
	//        pthread_setspecific(in_hook_key, (void*)1); // set in hook flag
	// 
	//        void* p = malloc(size);      // call malloc, it will not re-enter
	// 
	//        // your code here
	// 
	//        strdup("test");             // strdup call malloc, it will not re-enter
	// 
	//        // your code here
	// 
	//        pthread_setspecific(in_hook_key, nullptr); // clear in hook flag
	//    }
	//    return old_malloc(size);      // call old_func, if in the hook, directly callback the old function to avoid re-entry
	// }
	// 
	// GlossHook((void*)malloc, (void*)my_malloc, (void**)&old_malloc); // hook malloc
	// 
	// The above code should solve the re-entry problem, 
	// and there are other methods to solve the re-entry problem, such as using a bool variable to check the hook status, or use atomic variables.
	// GlossHook also provides a solution:
	//
	// GHook hook_handle = nullptr;      // hook handle
	// void* (*old_malloc)(size_t size); // old_func to store
	// void* my_malloc(size_t size)      // new_func
	// {
	//     static void* (*orig_malloc)(size_t size) = (void* (*)(size_t))GlossHookGetOriglFunc(hook_handle); // original malloc function
	// 
	//     // your code here
	// 
	//     void* p = orig_malloc(size);      // call orig_malloc, skip hook if in the my_malloc, will not re-enter
	// 
	//     // your code here
	// 
	//     // strdup("test");             // not support, will cause crash
	// 
	//     // your code here
	// 
	//     return old_malloc(size);      // call old_func, It will not re-enter because it is the old function returned by the hook
	// }
	// 
	// hook_handle = GlossHook((void*)malloc, (void*)my_malloc, (void**)&old_malloc); // hook malloc, get hook handle
	// 
	// However, it only applies to the case where the hook function is called directly,
	// and the case where other functions are called still causes re-entry.
	// 
	//

	/*
	* GlossHookAddTrampolines - Add trampolines memory to the library.
	*
	* @note: This function is used to add trampolines to the library, it can be used to solve the problem of limited jump range for 4-byte hooks.
	*
	* B/BL/BLX instructions have jump range limitations. GlossHook will allocate free memory within the range of the shared object (SO) to create a trampoline.
	* The nearby memory space of the SO is limited, To avoid reaching the automatic memory allocation limit,
	* you can add a memory range to be used as trampolines yourself. The starting address must be 4-byte aligned, within the range of branch instruction jumps.
	* and it should be free memory that is not used at runtime.
	* GlossHook will prioritize the added trampoline memory.
	*
	* @param lib_name - The library name (or path name) to add trampolines. (Cannot use NULL)
	* @param start_addr - The start address. (Absolute address, Cannot use NULL)
	* @param size - The size range. (Cannot use 0, ARM requires at least 8 bytes, ARM64 requires at least 16 bytes.)
	*/
	GLOSS_API void GlossHookAddTrampolines(const char* lib_name, uintptr_t start_addr, size_t size);

	/*
	* GlossHook - Inline hook function head by symbol address.
	*
	* @note: { sym_addr } must differentiate between thumb and arm. (e.g 0x12345679 or 0x12345678)
	*
	* If the function size is smaller than the jump instruction size,
	* the B instruction will automatically be used for a relative jump (the function must be at least 4 bytes).
	*
	* B instructions have jump range limitations. GlossHook will allocate free memory within the range of the shared object (SO) to create a trampoline.
	* The nearby memory space of the SO is limited, which can also lead to hook failures. (see { GlossHookAddTrampolines })
	*
	* @param sym_addr - The symbol address to hook. (Cannot use NULL)
	* @param new_func - The new function to hook. (Cannot use NULL)
	* @param old_func - The old function to store. (Can be NULL)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossHook(void* sym_addr, void* new_func, void** old_func);

	/*
	* GlossHookAddr - Inline hook function head by function address.
	*
	* @note: The parameter { i_set mode } differentiates between thumb, arm, and arm64 modes for the { func_addr }.
	*
	* B instructions have jump range limitations. GlossHook will allocate free memory within the range of the shared object (SO) to create a trampoline.
	* The nearby memory space of the SO is limited, which can also lead to hook failures. (see { GlossHookAddTrampolines })
	*
	* @param func_addr - The function address to hook. (Cannot use NULL)
	* @param new_func - The new function to hook. (Cannot use NULL)
	* @param old_func - The old function to store. (Can be NULL)
	* @param is_4_byte_hook - Whether to use 4-byte hook. (true: Jump with 4-byte B instruction, false: defautl)
	* @param mode - The hook mode. (see i_set)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossHookAddr(void* func_addr, void* new_func, void** old_func, bool is_4_byte_hook, i_set mode);

	/*
	* GlossHookBranch - Inline hook branch instruction. (BL, BLX)
	*
	* @note: The parameter { i_set mode } differentiates between thumb, arm, and arm64 modes for the { branch_addr }.
	*
	* BL and BLX instructions have jump range limitations. GlossHook will allocate free memory within the range of the shared object (SO) to create a trampoline.
	* The nearby memory space of the SO is limited, which can also lead to hook failures. (see { GlossHookAddTrampolines })
	*
	* @param branch_addr - The branch instruction address to hook. (Cannot use NULL)
	* @param new_func - The new function to hook. (Cannot use NULL)
	* @param old_func - The old function to store. (Can be NULL)
	* @param mode - The hook mode. (see i_set)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossHookBranchBL(void* branch_addr, void* new_func, void** old_func, i_set mode);
#ifdef __arm__
	GLOSS_API GHook GlossHookBranchBLX(void* branch_addr, void* new_func, void** old_func, i_set mode);
#endif 

	/*
	* GlossHookInternalCallback - Internal hook callback function.
	*
	* @param regs - The register information, see gloss_reg.
	* @param hook - The hook handle.
	*/
	typedef void (*GlossHookInternalCallback)(gloss_reg* regs, GHook hook);
	/*
	* GlossHookInternal - Inline hook executable code at any position, accessing register and stack information.
	*
	* @note: The parameter { i_set mode } differentiates between thumb, arm, and arm64 modes for the { addr }.
	*
	* B instructions have jump range limitations. GlossHook will allocate free memory within the range of the shared object (SO) to create a trampoline.
	* The nearby memory space of the SO is limited, which can also lead to hook failures. (see { GlossHookAddTrampolines })
	*
	* If ret_addr is set, it may break the ability to hook the address multiple times.
	*
	* @param addr - The address to hook. (Cannot use NULL)
	* @param new_func - The new function to hook, see GlossHookInternalCallback. (Cannot use NULL)
	* @param ret_addr - The return address of the new function. (Can be NULL, if it is NULL, default to jumping to the original instruction for execution)
	* @param is_4_byte_hook - Whether to use 4-byte hook. (true: Jump with 4-byte B instruction, false: defautl)
	* @param mode - The hook mode. (see i_set)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossHookInternal(void* addr, GlossHookInternalCallback new_func, void* ret_addr, bool is_4_byte_hook, i_set mode);

	/*
	* GlossHookRedirect - Redirect executable code at any position to a new address.
	*
	* @note: The parameter { i_set mode } differentiates between thumb, arm, and arm64 modes for the { redirect_addr }.
	*
	* B instructions have jump range limitations. GlossHook will allocate free memory within the range of the shared object (SO) to create a trampoline.
	* The nearby memory space of the SO is limited, which can also lead to hook failures.
	*
	* @param addr - The address to redirect. (Cannot use NULL)
	* @param new_addr - The new address to redirect. (Cannot use NULL)
	* @param is_4_byte_hook - Whether to use 4-byte hook. (true: Jump with 4-byte B instruction, false: defautl)
	* @param mode - The hook mode. (see i_set)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossHookRedirect(void* addr, void* new_addr, bool is_4_byte_hook, i_set mode);

	/*
	* GlossGotHook - Hook Global Offset Table
	*
	* @param got_addr - The GOT entry address to hook. (Cannot use NULL)
	* @param new_func - The new function to hook. (Cannot use NULL)
	* @param old_func - The old function to store. (Can be NULL)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossGotHook(void* got_addr, void* new_func, void** old_func);

	// GlossLinkerFuncProxy - Proxy for linker function.
	// Support function: dlopen, dlsym, other linker or libdl.so function.
	union GlossLinkerFuncProxy
	{
		struct GlossDlopenProxy
		{
			// API Level 19 (Android 4.4) and below - K
			void* (*dlopen)(const char* filename, int flags);
			void** old_dlopen;

			// API Level 21 - 23 (Android 5.0 - 6.0) - L L_MR1 M
			// Starting from Android 5.0, dlopen is divided into { dlopen } and { android_dlopen_ext } two functions.
			// dlopen and android_dlopen_ext -> dlopen_ext -> do_dlopen
			void* (*do_dlopen)(const char* filename, int flags, const void* extinfo);
			void** old_do_dlopen;

			// API Level 24 (Android 7.0) and above - N
			// dlopen and android_dlopen_ext -> dlopen_ext -> do_dlopen
			void* (*do_dlopen_n)(const char* filename, int flags, const void* extinfo, void* caller_addr);
			void** old_do_dlopen_n;

			// API Level 26 (Android 8.0) and above
			// dlopen and android_dlopen_ext -> __loader_dlopen and __loader_android_dlopen_ext -> dlopen_ext -> do_dlopen
			// Can hook { __loader_dlopen } or { __loader_android_dlopen_ext }
		} DlopenProxy;

		struct GlossDlsymProxy
		{
			// API Level 23 (Android 6.0) and below - M
			void* (*dlsym)(void* handle, const char* symbol);
			void** old_dlsym;

			// API Level 24 (Android 7.0) and above - N
			// dlsym and dlvsym -> dlsym_impl -> do_dlsym
			bool (*do_dlsym)(void* handle, const char* sym_name, const char* sym_ver, const void* caller_addr, void** symbol);
			void** old_do_dlsym;

			// API Level 26 (Android 8.0) and above
			// dlsym -> __loader_dlsym -> dlsym_impl -> do_dlsym
			// dlvsym -> __loader_dlvsym -> dlsym_impl -> do_dlsym
			// Can hook { __loader_dlsym } or { __loader_dlvsym }
		} DlsymProxy;

		// Other Linker Function
		struct GlossFuncProxy
		{
			// libdl.so or linker
			void* linker_func;
			void** old_linker_func;
		} FuncProxy;
	};
	/*
	* GlossLinkerHook - Hook linker and dl functions.
	*
	* @note: Starting from Android 7.0, due to the linker namespace limit, it is impossible to directly hook the dl series functions in the linker.
	* To implement hooking dl series functions, some special processing is done, and a separate API is provided to hook dl series functions.
	* Support hooking all symbols functions in the linker and libdl.so. (libdl.so was introduced in Android 8.0)
	* Android emulators may not be supported.
	*
	* @param dlfunc - The linker function c/c++ symbol name to hook. (Cannot use NULL)
	* @param new_dlfunc - The new linker function to hook, see GlossLinkerFuncProxy. (Cannot use NULL)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossLinkerHook(const char* dlfunc, GlossLinkerFuncProxy new_dlfunc);

	/*
	* GlossHookCallback_t - The callback function when the Hook becomes effective.
	*
	* @param hook - The hook handle.
	* @param lib_name - The library name (or path name).
	* @param addr - The symbol addr or got addr list.
	* @param size - The symbol size or got addr list size.
	*/
	struct GlossHookCallback_t
	{
		GHook hook; // hook handle
		const char* path; // lib_name or lib_path
		void* addr; // sym_addr or got_addr_list
		size_t size; // sym_size or got_addr_list_size
	};
	typedef void (*GlossHookCallback)(const GlossHookCallback_t info);

	/*
	* GlossHookByName - Inline hook function head by symbol name.
	*
	* @note: If the dynamic library has been loaded, the hook is completed immediately,
	* otherwise, it will be automatically hooked when the library is loaded in the future, need Enable init linke.(see GlossInit)
	* Android emulators may not be supported.
	*
	* @param lib_name - The library name (or path name) to hook. (Cannot use NULL)
	* @param sym_name - The symbol name to hook. (Cannot use NULL)
	* @param new_func - The new function to hook. (Cannot use NULL)
	* @param old_func - The old function to store. (Can be NULL)
	* @param call_back_func - The callback function when the hook is triggered, see GlossHookCallback_t. (Can be NULL)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossHookByName(const char* lib_name, const char* sym_name, void* new_func, void** old_func, GlossHookCallback call_back_func);

	/*
	* GlossPltHook - Hook Global Offset Table by symbol name
	*
	* @note: If the dynamic library has been loaded, the hook is completed immediately,
	* otherwise, it will be automatically hooked when the library is loaded in the future, need Enable init linke.(see GlossInit)
	* Android emulators may not be supported.
	*
	* @param lib_name - The library name (or path name) to hook. (Cannot use NULL)
	* @param sym_name - The symbol name to hook. (Cannot use NULL)
	* @param new_func - The new function to hook. (Cannot use NULL)
	* @param old_func - The old function to store. (Can be NULL)
	* @param call_back_func - The callback function when the hook is triggered, see GlossHookCallback_t. (Can be NULL)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossPltHook(const char* lib_name, const char* sym_name, void* new_func, void** old_func, GlossHookCallback call_back_func);

	/*
	* GlossHookConstructor - Inline hook constructor function.
	*
	* @note: If the dynamic library has been loaded, the hook is completed immediately,
	* otherwise, it will be automatically hooked when the library is loaded in the future, need Enable init linke.(see GlossInit)
	* Android emulators may not be supported.
	*
	* B instructions have jump range limitations. GlossHook will allocate free memory within the range of the shared object (SO) to create a trampoline.
	* The nearby memory space of the SO is limited, which can also lead to hook failures.
	* Android emulators may not be supported.
	*
	* @param lib_name - The library name (or path name) to hook. (Cannot use NULL)
	* @param offset_addr - The offset address of the constructor function. (Cannot use NULL)
	* @param new_func - The new function to hook. (Cannot use NULL)
	* @param old_func - The old function to store. (Can be NULL)
	* @param is_4_byte_hook - Whether to use 4-byte hook. (true: Jump with 4-byte B instruction, false: defautl)
	* @param mode - The hook mode. (see i_set)
	* @param call_back_func - The callback function when the hook is triggered, see GlossHookCallback_t. (Can be NULL)
	* @return The hook handle. (failed: NULL)
	*/
	GLOSS_API GHook GlossHookConstructor(const char* lib_name, uintptr_t offset_addr, void* new_func, void** old_func, bool is_4_byte_hook, i_set mode, GlossHookCallback call_back_func);

	/*
	* GlossHookDisable/Enable/Delete - Disable/Enable/Delete hook.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	*/
	GLOSS_API void GlossHookDisable(GHook hook);
	GLOSS_API void GlossHookEnable(GHook hook);
	GLOSS_API void GlossHookDelete(GHook hook);
	/*
	* All - Disable/Enable/Delete all hooks from the specified address.
	*
	* @param addr - The address to disable/enable/delete hooks. (Cannot use NULL)
	* @param mode - The hook mode. (see i_set)
	*/
	GLOSS_API void GlossDisableAllHook(void* addr, i_set mode);
	GLOSS_API void GlossEnableAllHook(void* addr, i_set mode);
	GLOSS_API void GlossDeleteAllHook(void* addr, i_set mode);

	/*
	* GlossHookGetCount - Get the current hook count id.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	* @return Count id. (0: failed)
	*/
	GLOSS_API int GlossHookGetCount(GHook hook);
	/*
	* GlossHookGetTotalCount - Get the hook total count id from the specified address.
	*
	* @param addr - The address to get hook total count. (Cannot use NULL)
	* @param inst_set - The instruction set. (see i_set)
	* @return Total count id. (0: failed)
	*/
	GLOSS_API int GlossHookGetTotalCount(void* addr, i_set inst_set);

	/*
	* GlossHookGetLastHook - Get the last hook handle from the specified address.
	*
	* @param addr - The address to get last hook handle. (Cannot use NULL)
	* @param inst_set - The instruction set. (see i_set)
	* @return The last hook handle. (NULL: failed)
	*/
	GLOSS_API GHook GlossHookGetLastHook(void* addr, i_set inst_set);

	/*
	* GlossHookGetPrevHook - Get the previous hook handle.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	* @return The previous hook handle. (NULL: failed)
	*/
	GLOSS_API GHook GlossHookGetPrevHook(GHook hook);

	/*
	* GlossHookGetNextHook - Get the next hook handle.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	* @return The next hook handle. (NULL: failed)
	*/
	GLOSS_API GHook GlossHookGetNextHook(GHook hook);

	/*
	* GlossHookReplaceNewFunc - Replace the new function of the hook.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	* @param new_func - The new function to replace. (Cannot use NULL)
	*/
	GLOSS_API void GlossHookReplaceNewFunc(GHook hook, void* new_func);

	/*
	* GlossHookGetOldFunc - Get the old function of the hook.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	* @return The old function. (NULL: failed)
	*/
	GLOSS_API void* GlossHookGetOldFunc(GHook hook);

	/*
	* GlossHookGetOriglFunc - Get the original function of the hook.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	* @return The original function. (NULL: failed)
	*/
	GLOSS_API void* GlossHookGetOriglFunc(GHook hook);

	/*
	* GlossHookGetInstBuffer - Get the fixed original instruction buffer of the hook.
	*
	* @param hook - The hook handle. (Cannot use NULL)
	* @return The original instruction buffer. (NULL: failed)
	*/
	GLOSS_API uint8_t* GlossHookGetInstBuffer(GHook hook);

#ifdef __cplusplus
}
	/*
	* Write any type of value to memory.
	*/
	template <typename T>
	inline static void WriteMemory(uintptr_t addr, T value, bool vp = true)
	{
		WriteMemory(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(&value), sizeof(T), vp);
	}

	/*
	* Read any type of value from memory.
	*/
	template <typename T>
	inline static T ReadMemory(uintptr_t addr, bool vp = true)
	{
		T value;
		ReadMemory(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(&value), sizeof(T), vp);
		return value;
	}


// *********************************************************** Inst API ******************************************************************************
// GlossHook Inst.h
#ifndef GLOSS_HOOK_INST_H
#define GLOSS_HOOK_INST_H
	
	namespace Gloss {
		namespace Inst {
			int CheckAbsoluteJump(uintptr_t addr);
			int CheckRelativeJump(uintptr_t addr);

			// conditions type
			enum class Conds { EQ, NE, CS, HS = CS, CC, LO = CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV, MAX_COND };

			// branchs type
			enum class Branchs { B_COND16, B_COND, B_16, B, BL, BLX, MAX_BRANCH };
			/*
			* GetBranch - Get branch instruction type of addr.
			*
			* @param addr - Address to get branch type.
			* @param mode - The instruction mode. (see i_set)
			* @return - Branch type. (see branchs)
			*/
			GLOSS_API Branchs GetBranch(uintptr_t addr, i_set mode);

#ifdef __arm__

			/*
			* IsThumb32 - Check if addr is thumb32 instruction.
			*
			* @param addr - Address to check.
			* @return - True if addr is thumb32 instruction, otherwise false.
			*/
			GLOSS_API bool IsThumb32(uint32_t addr);

			/*
			* MakeNOP - Make nop instruction. (thumb16/32)
			*
			* @param addr - Address to make nop instruction.
			* @param size - The byte size of the instruction.
			*/
			GLOSS_API void MakeThumb16NOP(uint32_t addr, size_t size);
			GLOSS_API void MakeThumb32NOP(uint32_t addr, size_t size);

			/*
			* MakeRET - Make function return instruction. (thumb16)
			*
			* @param addr - Address to make return instruction.
			* @param type - The instruction type. ( 1: BX LR, 0: MOV PC, LR)
			*/
			GLOSS_API void MakeThumbRET(uint32_t addr, uint8_t type);

			/*
			* MakeBranch - Make branch instruction. (thumb16/32 B BC BL BLX)
			*
			* @param addr - Address to make branch instruction.
			* @param dest - The branch destination.
			* @param cond - The branch condition. (see conds)
			* @return - The branch instruction.
			*/
			GLOSS_API uint16_t MakeThumb16B(uint32_t addr, uint32_t dest);
			GLOSS_API uint16_t MakeThumb16BCond(uint32_t addr, uint32_t dest, Conds cond);
			GLOSS_API uint32_t MakeThumb32B(uint32_t addr, uint32_t dest);
			GLOSS_API uint32_t MakeThumb32BCond(uint32_t addr, uint32_t dest, Conds cond);
			GLOSS_API uint32_t MakeThumbBL(uint32_t addr, uint32_t func);
			GLOSS_API uint32_t MakeThumbBL_W(uint32_t addr, uint32_t func);
			GLOSS_API uint32_t MakeThumbBLX(uint32_t addr, uint32_t func);
			GLOSS_API uint32_t MakeThumbBLX_W(uint32_t addr, uint32_t func);

			/*
			* MakeCB - Make conditional branch instruction. (thumb16)
			*
			* @param addr - Address to make conditional branch instruction.
			* @param dest - The branch destination.
			* @param reg - The condition register. (see gloss_reg::e_reg)
			* @param is_cbnz - True if the instruction is CBNZ, otherwise CBZ.
			* @return - The conditional branch instruction.
			*/
			GLOSS_API uint16_t MakeThumbCB(uint32_t addr, uint32_t dest, gloss_reg::e_reg reg, bool is_cbnz);

			/*
			* MakeAbsoluteJump - Make absolute jump instruction. (thumb32)
			*
			* Inst;
			* addr[0] LDR.W PC, [PC, #0]
			* addr[4] dest
			*
			* @param addr - Address to make absolute jump instruction.
			* @param dest - The absolute jump destination.
			* @return - The absolute jump instruction byte size.
			*/
			GLOSS_API int8_t MakeThumbAbsoluteJump(uint32_t addr, uint32_t dest);

			/*
			* GetBranchDestination - Get branch destination. (thumb16/32)
			*
			* @param addr - Address to get branch destination.
			* @return - The branch destination address.
			*/
			GLOSS_API uint32_t GetThumb16BranchDestination(uint32_t addr);
			GLOSS_API uint32_t GetThumb32BranchDestination(uint32_t addr);

			/*
			* MakeNOP - Make nop instruction. (arm)
			*
			* @param addr - Address to make nop instruction.
			* @param size - The byte size of the instruction.
			*/
			GLOSS_API void MakeArmNOP(uint32_t addr, size_t size);

			/*
			* MakeRET - Make function return instruction. (arm)
			*
			* @param addr - Address to make return instruction.
			* @param type - The instruction type. ( 1: BX LR, 0: MOV PC, LR)
			*/
			GLOSS_API void MakeArmRET(uint32_t addr, uint8_t type);

			/*
			* MakeBranch - Make branch instruction. (arm B BC BL BLX)
			*
			* @param addr - Address to make branch instruction.
			* @param dest - The branch destination.
			* @param cond - The branch condition. (see conds)
			* @return - The branch instruction.
			*/
			GLOSS_API uint32_t MakeArmB(uint32_t addr, uint32_t dest, Conds cond = Conds::AL);
			GLOSS_API uint32_t MakeArmBL(uint32_t addr, uint32_t func, Conds cond = Conds::AL);
			GLOSS_API uint32_t MakeArmBLX(uint32_t addr, uint32_t func);

			/*
			* MakeAbsoluteJump - Make absolute jump instruction. (arm)
			*
			* Inst;
			* addr[0] LDR PC, [PC, #-4]
			* addr[4] dest
			*
			* @param addr - Address to make absolute jump instruction.
			* @param dest - The absolute jump destination.
			* @return - The absolute jump instruction byte size.
			*/
			GLOSS_API int8_t MakeArmAbsoluteJump(uint32_t addr, uint32_t dest);

			/*
			* GetBranchDestination - Get branch destination. (arm)
			*
			* @param addr - Address to get branch destination.
			* @return - The branch destination address.
			*/
			GLOSS_API uint32_t GetArmBranchDestination(uint32_t addr);

#elif __aarch64__

			/*
			* MakeNOP - Make nop instruction. (aarch64)
			*
			* @param addr - Address to make nop instruction.
			* @param size - The byte size of the instruction.
			*/
			GLOSS_API void MakeArm64NOP(uint64_t addr, size_t size);

			/*
			* MakeRET - Make function return instruction. (aarch64)
			*
			* @param addr - Address to make return instruction.
			* @param type - The instruction type. ( 1: BR X30(LR) 0: RET)
			*/
			GLOSS_API void MakeArm64RET(uint64_t addr, uint8_t type);

			/*
			* MakeBranch - Make branch instruction. (aarch64 B BC BL)
			*
			* @param addr - Address to make branch instruction.
			* @param dest - The branch destination.
			* @param cond - The branch condition. (see conds)
			* @return - The branch instruction.
			*/
			GLOSS_API uint32_t MakeArm64B(uint64_t addr, uint64_t dest);
			GLOSS_API uint32_t MakeArm64BCond(uint64_t addr, uint64_t dest, Conds cond);
			GLOSS_API uint32_t MakeArm64BL(uint64_t addr, uint64_t func);

			/*
			* MakeCB - Make conditional branch instruction. (aarch64)
			*
			* @param addr - Address to make conditional branch instruction.
			* @param dest - The branch destination.
			* @param reg - The condition register. (see gloss_reg::e_reg)
			* @param is_cbnz - True if the instruction is CBNZ, otherwise CBZ.
			* @param is64 - True if the register is 64bit, otherwise 32bit.
			* @return - The conditional branch instruction.
			*/
			GLOSS_API uint32_t MakeArm64CB(uint64_t addr, uint64_t dest, gloss_reg::e_reg reg, bool is_cbnz, bool is64);

			/*
			* MakeAbsoluteJump - Make absolute jump instruction. (aarch64)
			*
			* Inst; (Jump)
			* addr[0] LDR X18, #8
			* addr[4] BR X18
			* addr[8] dest
			*
			* Inst; (JumpRet)
			* addr[0] LDR X18, #8
			* addr[4] RET X18
			* addr[8] dest
			*
			* Inst; (Jump32)
			* addr[0] ADRP X18, dest
			* addr[4] BR X18
			*
			* Inst; (Jump128)
			* addr[0] STP X1, X0, [SP, #-0x10]
			* addr[4] LDR X0, 8
			* addr[8] BR X0
			* addr[12] dest
			* addr[20] LDR X0, [SP, -0x8]
			*
			* @param addr - Address to make absolute jump instruction.
			* @param dest - The absolute jump destination.
			* @param reg - The register to store the jump address. (see gloss_reg::e_reg)
			* @return - The absolute jump instruction byte size.
			*/
			GLOSS_API int8_t MakeArm64AbsoluteJump(uint64_t addr, uint64_t dest, gloss_reg::e_reg reg = gloss_reg::e_reg::X18); // unlimited
			GLOSS_API int8_t MakeArm64AbsoluteJumpRet(uint64_t addr, uint64_t dest, gloss_reg::e_reg reg = gloss_reg::e_reg::X18); // unlimited
			GLOSS_API int8_t MakeArm64AbsoluteJump32(uint64_t addr, uint64_t dest, gloss_reg::e_reg reg = gloss_reg::e_reg::X18); // 4g limit
			GLOSS_API int8_t MakeArm64AbsoluteJump128(uint64_t addr, uint64_t dest); // unlimited

			/*
			* GetBranchDestination - Get branch destination. (aarch64)
			*
			* @param addr - Address to get branch destination.
			* @return - The branch destination address.
			*/
			GLOSS_API uint64_t GetArm64BranchDestination(uint64_t addr);

#endif 
		}
	}
#endif

#endif
#endif