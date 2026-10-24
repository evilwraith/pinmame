# ---------------------------------------------------------------------------
#  Optional P-ROC game subsystem (src/procgame)
#
#  ON by default where it can run (Linux, macOS): a P-ROC game is a Python
#  program run as a separate process through fork/exec and POSIX shared
#  memory. Disable with -DPINMAME_PROCGAME=OFF, which leaves neither
#  src/wpc/procgame.c's games nor the P-ROC game CPU registered.
#
#  Like the Spike 1 subsystem (cmake/spike1.cmake) it is its own OBJECT
#  library: it is C++17 and includes no PinMAME header; src/wpc/procgame.c,
#  PinMAME's half, is built with the consumer's own settings.
#
#  Usage in a top-level CMakeLists:
#      include(${CMAKE_SOURCE_DIR}/cmake/procgame.cmake)
#      pinmame_enable_procgame(<target>)
# ---------------------------------------------------------------------------

if(UNIX)
   option(PINMAME_PROCGAME "Build the P-ROC game subsystem (src/procgame)" ON)
else()
   option(PINMAME_PROCGAME "Build the P-ROC game subsystem (src/procgame)" OFF)
endif()

set(_PINMAME_PROCGAME_LIST_DIR ${CMAKE_CURRENT_LIST_DIR})

function(_pinmame_procgame_add_library reference_target)
   add_library(procgame OBJECT
      ${_PINMAME_PROCGAME_LIST_DIR}/../src/procgame/ProcBridge.cpp
      ${_PINMAME_PROCGAME_LIST_DIR}/../src/procgame/procgame_pinmame.cpp
   )
   set_target_properties(procgame PROPERTIES
      CXX_STANDARD 17
      CXX_STANDARD_REQUIRED ON
      POSITION_INDEPENDENT_CODE ON
   )
   get_target_property(_rt ${reference_target} MSVC_RUNTIME_LIBRARY)
   if(_rt)
      set_target_properties(procgame PROPERTIES MSVC_RUNTIME_LIBRARY "${_rt}")
   endif()
endfunction()

# Attach the P-ROC game subsystem to a pinmame target. No-op unless PINMAME_PROCGAME is ON.
function(pinmame_enable_procgame target)
   if(NOT PINMAME_PROCGAME)
      return()
   endif()
   if(NOT TARGET procgame)
      _pinmame_procgame_add_library(${target})
   endif()
   # src/wpc/procgame.c is PinMAME's half - CPU interface, machine driver, sets, I/O, display,
   # sound - wrapped in #if HAS_PROCGAME, the switch src/wpc/driver.c and src/cpuintrf.c test too
   target_sources(${target} PRIVATE
      ${_PINMAME_PROCGAME_LIST_DIR}/../src/wpc/procgame.c
      $<TARGET_OBJECTS:procgame>
   )
   target_compile_definitions(${target} PRIVATE HAS_PROCGAME=1)
   if(NOT APPLE)
      target_link_libraries(${target} PRIVATE rt dl)
   endif()
endfunction()
