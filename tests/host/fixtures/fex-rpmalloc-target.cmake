# Exact excerpt of FEXCore/Source/CMakeLists.txt at 1adb337a2f2270434ba731346438c072337a5d5f.
# Meta-library to link jemalloc libraries enabled in the build configuration.
# Only needed for targets that run emulation. For others, use JemallocDummy.
add_library(JemallocLibs STATIC Utils/AllocatorHooks.cpp)
if (ENABLE_FEX_ALLOCATOR)
  target_compile_definitions(JemallocLibs PRIVATE ENABLE_FEX_ALLOCATOR=1)
  target_link_libraries(JemallocLibs PUBLIC rpmalloc)
endif()
if (ENABLE_JEMALLOC_GLIBC_ALLOC)
  set_source_files_properties(Interface/HLE/Thunks/Thunks.cpp PROPERTIES COMPILE_DEFINITIONS ENABLE_JEMALLOC_GLIBC=1)
  target_link_libraries(JemallocLibs INTERFACE FEX_jemalloc_glibc)
endif()

