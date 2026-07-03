cmake_minimum_required(VERSION 3.16)
project(vinfast_scanner VERSION 1.0.1 LANGUAGES C CXX OBJCXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# -------------------------------------------------------------------
# Windows: this is a 32-bit (x86) build.
#
# The CAN/OBD-II backup transport loads Toyota's Mini-VCI J2534 driver
# (mvci32.dll), which is a 32-bit DLL. A 64-bit process CANNOT load a 32-bit
# DLL - LoadLibrary fails with ERROR_BAD_EXE_FORMAT (193) - so the entire app
# must be built as x86 on Windows. Configure a *separate* 32-bit build tree:
#
#   Visual Studio:  cmake -A Win32 -S . -B build-win32
#                   cmake --build build-win32 --config Release
#   MinGW (i686):   configure with a 32-bit i686-w64-mingw32 toolchain
#
# The guard below makes a mismatched 64-bit Windows build fail fast with a
# clear message instead of failing at runtime when mvci32.dll won't load.
# Set -DALLOW_WIN64=ON only if you knowingly want a 64-bit build WITHOUT the
# Mini-VCI CAN backup (OpenXC Bluetooth transport still works).
# -------------------------------------------------------------------
option(ALLOW_WIN64 "Permit a 64-bit Windows build (disables Mini-VCI CAN backup at runtime)" OFF)
if(WIN32 AND NOT ALLOW_WIN64 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR
    "vinfast_scanner must be built as 32-bit (x86) on Windows: Toyota's Mini-VCI "
    "J2534 driver (mvci32.dll) is a 32-bit DLL and a 64-bit process cannot load "
    "it. OpenXC Bluetooth is not available on Windows; the CAN backup is the only transport.\n"
    "  Visual Studio:  cmake -A Win32 -S . -B build-win32\n"
    "  MinGW:          use a 32-bit (i686-w64-mingw32) toolchain\n"
    "Or pass -DALLOW_WIN64=ON to build 64-bit without the CAN backup.")
endif()
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(STATUS "vinfast_scanner: 32-bit (x86) Windows build - Mini-VCI mvci32.dll loadable.")
endif()

# Qt code-generation (moc/uic/rcc) must run automatically.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

if(APPLE AND NOT CMAKE_PREFIX_PATH)
  execute_process(COMMAND brew --prefix qt
                  OUTPUT_VARIABLE _brew_qt
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  if(_brew_qt)
    list(APPEND CMAKE_PREFIX_PATH "${_brew_qt}")
  endif()
endif()

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# libcurl powers the (reverse-engineered, community) VinFast connected-car
# cloud client. Present by default on macOS and most Linux distros.
find_package(CURL REQUIRED)

# -------------------------------------------------------------------
# OpenXC C libraries (github.com/openxc)
#   uds-c   – UDS / OBD-II request+response types (depends on isotp-c)
#   isotp-c – ISO-TP (ISO 15765-2) framing        (depends on bitfield-c)
#   bitfield-c – Bitfield / CAN-signal utilities
#
# None of these projects ship a CMakeLists.txt, so we use
# FetchContent_Populate (download only) and define our own STATIC targets.
# -------------------------------------------------------------------
include(FetchContent)

# Suppress deprecation warning for FetchContent_Populate (used for libs
# without their own CMakeLists.txt).
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

FetchContent_Declare(bitfield_c
    GIT_REPOSITORY https://github.com/openxc/bitfield-c.git
    GIT_TAG        master)
FetchContent_Declare(isotp_c
    GIT_REPOSITORY https://github.com/openxc/isotp-c.git
    GIT_TAG        master)
FetchContent_Declare(uds_c
    GIT_REPOSITORY https://github.com/openxc/uds-c.git
    GIT_TAG        master)

FetchContent_GetProperties(bitfield_c)
if(NOT bitfield_c_POPULATED)
    FetchContent_Populate(bitfield_c)
endif()

FetchContent_GetProperties(isotp_c)
if(NOT isotp_c_POPULATED)
    FetchContent_Populate(isotp_c)
endif()

FetchContent_GetProperties(uds_c)
if(NOT uds_c_POPULATED)
    FetchContent_Populate(uds_c)
endif()

# bitfield-c: bitfield + CAN-signal utilities
file(GLOB BITFIELD_C_SOURCES
    "${bitfield_c_SOURCE_DIR}/src/bitfield/*.c"
    "${bitfield_c_SOURCE_DIR}/src/canutil/*.c")
add_library(openxc_bitfield STATIC ${BITFIELD_C_SOURCES})
target_include_directories(openxc_bitfield PUBLIC "${bitfield_c_SOURCE_DIR}/src")

# isotp-c: depends on bitfield-c headers at <bitfield/...>
file(GLOB ISOTP_C_SOURCES "${isotp_c_SOURCE_DIR}/src/isotp/*.c")
add_library(openxc_isotp STATIC ${ISOTP_C_SOURCES})
target_include_directories(openxc_isotp PUBLIC
    "${isotp_c_SOURCE_DIR}/src"
    "${bitfield_c_SOURCE_DIR}/src")   # resolves <bitfield/bitfield.h>
target_link_libraries(openxc_isotp PUBLIC openxc_bitfield)

# uds-c: depends on isotp-c headers at <isotp/...>
file(GLOB UDS_C_SOURCES "${uds_c_SOURCE_DIR}/src/uds/*.c")
add_library(openxc_uds STATIC ${UDS_C_SOURCES})
target_include_directories(openxc_uds PUBLIC
    "${uds_c_SOURCE_DIR}/src"
    "${isotp_c_SOURCE_DIR}/src"
    "${bitfield_c_SOURCE_DIR}/src")
target_link_libraries(openxc_uds PUBLIC openxc_isotp)

# -------------------------------------------------------------------
# Application
# -------------------------------------------------------------------
# On macOS, bundle the app icon into the generated .app so macdeployqt
# produces a self-contained, double-clickable application.
set(_app_macos_icon "${CMAKE_CURRENT_SOURCE_DIR}/assets/images/vinfast-vf8.icns")
set(_app_sources
  src/main.cpp
  src/Logger.cpp
  src/OpenXcClient.cpp
  src/OpenXcTransport.cpp
  src/BtDiscovery.mm
  src/CanClient.cpp
  src/UDSClient.cpp
  src/VF8Data.cpp
  src/CloudData.cpp
  src/CloudClient.cpp
  src/Gui.cpp
  assets/resources.qrc
)
if(APPLE AND EXISTS "${_app_macos_icon}")
  list(APPEND _app_sources "${_app_macos_icon}")
endif()

add_executable(vinfast_scanner MACOSX_BUNDLE ${_app_sources})
target_include_directories(vinfast_scanner PRIVATE src)
target_link_libraries(vinfast_scanner PRIVATE Qt6::Widgets CURL::libcurl openxc_uds)

if(WIN32)
  target_link_libraries(vinfast_scanner PRIVATE ws2_32 iphlpapi)
endif()

if(APPLE)
  target_link_libraries(vinfast_scanner PRIVATE
    "-framework Cocoa" "-framework IOKit" "-framework CoreVideo"
    "-framework IOBluetooth")

  if(EXISTS "${_app_macos_icon}")
    set_source_files_properties("${_app_macos_icon}" PROPERTIES
      MACOSX_PACKAGE_LOCATION "Resources")
    set(MACOSX_BUNDLE_ICON_FILE "vinfast-vf8.icns")
  endif()

  set_target_properties(vinfast_scanner PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME "VinFast Scanner"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.vinfast.diagnostics.scanner"
    MACOSX_BUNDLE_BUNDLE_VERSION "1.0.1"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.1")
endif()

