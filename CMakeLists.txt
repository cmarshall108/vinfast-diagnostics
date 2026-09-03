cmake_minimum_required(VERSION 3.16)
project(vinfast_scanner VERSION 1.0.1 LANGUAGES C CXX)

if(APPLE)
  enable_language(OBJCXX)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# -------------------------------------------------------------------
# Windows Mini-VCI CAN backup note.
#
# The CAN/OBD-II backup transport loads Toyota's Mini-VCI J2534 driver
# (mvci32.dll), which is a 32-bit DLL. A 64-bit process CANNOT load a 32-bit
# DLL - LoadLibrary fails with ERROR_BAD_EXE_FORMAT (193) - so Mini-VCI support
# requires an x86 Windows build. OpenXC USB serial works in 64-bit builds.
# Configure a separate 32-bit build tree when Mini-VCI backup is required:
#
#   Visual Studio:  cmake -A Win32 -S . -B build-win32
#                   cmake --build build-win32 --config Release
#   MinGW (i686):   configure with a 32-bit i686-w64-mingw32 toolchain
#
# 64-bit Windows builds are allowed; CanClient compiles to a clear runtime stub
# for the Mini-VCI-only backup path while the OpenXC USB serial path remains
# available.
# -------------------------------------------------------------------
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(STATUS "vinfast_scanner: 64-bit Windows build - OpenXC USB enabled; Mini-VCI CAN backup disabled.")
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

# isotp-c uses GCC's deprecated `field: value` initializer extension. MSVC
# requires the standard C99 spelling instead.
if(MSVC)
  foreach(_isotp_source IN ITEMS
      "${isotp_c_SOURCE_DIR}/src/isotp/isotp.c"
      "${isotp_c_SOURCE_DIR}/src/isotp/receive.c"
      "${isotp_c_SOURCE_DIR}/src/isotp/send.c")
    file(READ "${_isotp_source}" _isotp_contents)
    foreach(_isotp_field IN ITEMS
        log send_can_message set_timer frame_padding success completed
        arbitration_id size message_received_callback multi_frame payload)
      string(REGEX REPLACE
        "${_isotp_field}[ \t]*:" ".${_isotp_field} ="
        _isotp_contents "${_isotp_contents}")
    endforeach()
    file(WRITE "${_isotp_source}" "${_isotp_contents}")
  endforeach()
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
  src/CanClient.cpp
  src/UDSClient.cpp
  src/VF8Data.cpp
  src/CloudData.cpp
  src/CloudClient.cpp
  src/Gui.cpp
  assets/resources.qrc
)
if(APPLE)
  list(APPEND _app_sources src/BtDiscovery.mm)
else()
  list(APPEND _app_sources src/BtDiscovery.cpp)
endif()
if(APPLE AND EXISTS "${_app_macos_icon}")
  list(APPEND _app_sources "${_app_macos_icon}")
endif()

add_executable(vinfast_scanner MACOSX_BUNDLE ${_app_sources})
target_include_directories(vinfast_scanner PRIVATE src)
target_link_libraries(vinfast_scanner PRIVATE Qt6::Widgets CURL::libcurl openxc_uds)

if(WIN32)
  target_link_libraries(vinfast_scanner PRIVATE ws2_32 iphlpapi)
endif()

# -------------------------------------------------------------------
# Optional: native raw-USB transport for the OpenXC VI (libusb-1.0)
#
# The stock Ford OpenXC VI exposes a vendor-specific USB interface
# (class 0xFF, bulk endpoints) instead of a USB-CDC serial port, so on
# macOS no /dev/cu.* node appears and the serial backend can't reach it.
# When libusb-1.0 is available we compile a direct bulk-transfer backend
# (OPENXC_HAVE_LIBUSB) so "usb" connects straight to the VI.
# -------------------------------------------------------------------
find_path(LIBUSB_INCLUDE_DIR
  NAMES libusb.h
  PATH_SUFFIXES libusb-1.0
  HINTS
    /opt/homebrew/opt/libusb/include
    /usr/local/opt/libusb/include
    /opt/homebrew/include
    /usr/local/include
    /usr/include)
find_library(LIBUSB_LIBRARY
  NAMES usb-1.0 libusb-1.0
  HINTS
    /opt/homebrew/opt/libusb/lib
    /usr/local/opt/libusb/lib
    /opt/homebrew/lib
    /usr/local/lib
    /usr/lib)

if(LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARY)
  target_include_directories(vinfast_scanner PRIVATE "${LIBUSB_INCLUDE_DIR}")
  target_link_libraries(vinfast_scanner PRIVATE "${LIBUSB_LIBRARY}")
  target_compile_definitions(vinfast_scanner PRIVATE OPENXC_HAVE_LIBUSB=1)
  message(STATUS "libusb-1.0 found (${LIBUSB_LIBRARY}) - native OpenXC USB transport ENABLED")
else()
  message(STATUS "libusb-1.0 not found - native OpenXC USB transport DISABLED (serial/Bluetooth only)")
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

