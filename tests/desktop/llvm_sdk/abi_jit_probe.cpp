// SPDX-License-Identifier: MIT
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include "llvm/Config/llvm-config.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/MCJIT.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CBindingWrapping.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm-c/Core.h"
#include "llvm-c/Error.h"
#include "llvm-c/Transforms/PassBuilder.h"

#if !defined(_MSC_VER) || !defined(_M_X64) || !defined(_MT) || defined(_DLL)
#error This probe requires the x64 MSVC ABI and static release CRT (/MT)
#endif
#if defined(_DEBUG) || _ITERATOR_DEBUG_LEVEL != 0
#error Debug C++ ABI is not accepted
#endif
#if LLVM_VERSION_MAJOR != 22 || LLVM_VERSION_MINOR != 1 || LLVM_VERSION_PATCH != 4
#error Wrong LLVM SDK headers
#endif
static_assert(sizeof(void *) == 8, "64-bit pointer ABI required");

int main() {
  if (llvm::InitializeNativeTarget() || llvm::InitializeNativeTargetAsmPrinter() ||
      llvm::InitializeNativeTargetAsmParser()) return 11;
  LLVMLinkInMCJIT();
  llvm::LLVMContext context;
  auto module = std::make_unique<llvm::Module>("madeira-sdk-probe", context);
  llvm::IRBuilder<> builder(context);
  auto *i64 = builder.getInt64Ty();
  auto *type = llvm::FunctionType::get(i64, {i64, i64}, false);
  auto *function = llvm::Function::Create(type, llvm::Function::ExternalLinkage,
                                        "madeira_sdk_mix", module.get());
  auto *block = llvm::BasicBlock::Create(context, "entry", function);
  builder.SetInsertPoint(block);
  auto arg = function->arg_begin();
  llvm::Value *x = &*arg++;
  llvm::Value *y = &*arg;
  auto *mul = builder.CreateMul(x, builder.getInt64(UINT64_C(6364136223846793005)));
  auto *add = builder.CreateAdd(y, builder.getInt64(UINT64_C(1442695040888963407)));
  builder.CreateRet(builder.CreateXor(mul, add));
  if (llvm::verifyModule(*module, &llvm::errs())) return 12;
  LLVMPassBuilderOptionsRef options = LLVMCreatePassBuilderOptions();
  LLVMErrorRef error = LLVMRunPasses(llvm::wrap(module.get()), "default<O1>", nullptr, options);
  LLVMDisposePassBuilderOptions(options);
  if (error) {
    char *message = LLVMGetErrorMessage(error);
    std::fprintf(stderr, "FAIL passes=%s\n", message);
    LLVMDisposeErrorMessage(message);
    return 13;
  }
  if (llvm::verifyModule(*module, &llvm::errs())) return 14;
  char *printed = LLVMPrintModuleToString(llvm::wrap(module.get()));
  if (!printed || std::string(printed).find("madeira_sdk_mix") == std::string::npos) return 15;
  LLVMDisposeMessage(printed);
  std::string engine_error;
  std::unique_ptr<llvm::ExecutionEngine> engine(
    llvm::EngineBuilder(std::move(module)).setEngineKind(llvm::EngineKind::JIT)
      .setErrorStr(&engine_error).setOptLevel(llvm::CodeGenOptLevel::Default)
      .setMCJITMemoryManager(std::make_unique<llvm::SectionMemoryManager>()).create());
  if (!engine) {
    std::fprintf(stderr, "FAIL engine=%s\n", engine_error.c_str());
    return 16;
  }
  engine->finalizeObject();
  const auto address = engine->getFunctionAddress("madeira_sdk_mix");
  if (!address) return 17;
  MEMORY_BASIC_INFORMATION info{};
  if (!VirtualQuery(reinterpret_cast<void *>(address), &info, sizeof(info)) ||
      info.State != MEM_COMMIT ||
      !(info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
    return 18;
  using JitFunction = std::uint64_t (*)(std::uint64_t, std::uint64_t);
  auto mix = reinterpret_cast<JitFunction>(address);
  const std::uint64_t pairs[][2] = {{7, 19}, {UINT64_C(0x123456789abcdef0), 211}};
  for (unsigned n = 0; n < 2; ++n) {
    volatile std::uint64_t x_seed = pairs[n][0], y_seed = pairs[n][1];
    const std::uint64_t expected = (x_seed * UINT64_C(6364136223846793005)) ^
                                 (y_seed + UINT64_C(1442695040888963407));
    const auto actual = mix(x_seed, y_seed);
    if (actual != expected) return 19;
    std::printf("JIT seed=%u x=%llu y=%llu value=%llu\n", n,
      static_cast<unsigned long long>(x_seed), static_cast<unsigned long long>(y_seed),
      static_cast<unsigned long long>(actual));
  }
  engine.reset();
  std::printf("PASS llvm=%s abi=msvc-x64 crt=MT pointer_bits=64 passes=O1 jit=MCJIT seeds=2 cleanup=complete\n",
              LLVM_VERSION_STRING);
  return 0;
}
