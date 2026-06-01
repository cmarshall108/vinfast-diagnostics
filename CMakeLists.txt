cmake_minimum_required(VERSION 3.16)
project(vinfast_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
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
# Application
# -------------------------------------------------------------------
# On macOS, bundle the app icon into the generated .app so macdeployqt
# produces a self-contained, double-clickable application.
set(_app_macos_icon "${CMAKE_CURRENT_SOURCE_DIR}/assets/images/vinfast-vf8.icns")
set(_app_sources
  src/main.cpp
  src/Logger.cpp
  src/DoIPClient.cpp
  src/UDSClient.cpp
  src/VF8Data.cpp
  src/CloudData.cpp
  src/CloudClient.cpp
  src/Gui.cpp
)
if(APPLE AND EXISTS "${_app_macos_icon}")
  list(APPEND _app_sources "${_app_macos_icon}")
endif()

add_executable(vinfast_scanner MACOSX_BUNDLE ${_app_sources})
target_include_directories(vinfast_scanner PRIVATE src)
target_link_libraries(vinfast_scanner PRIVATE Qt6::Widgets CURL::libcurl)

if(WIN32)
  target_link_libraries(vinfast_scanner PRIVATE ws2_32 iphlpapi)
endif()

if(APPLE)
  target_link_libraries(vinfast_scanner PRIVATE
    "-framework Cocoa" "-framework IOKit" "-framework CoreVideo")

  if(EXISTS "${_app_macos_icon}")
    set_source_files_properties("${_app_macos_icon}" PROPERTIES
      MACOSX_PACKAGE_LOCATION "Resources")
    set(MACOSX_BUNDLE_ICON_FILE "vinfast-vf8.icns")
  endif()

  set_target_properties(vinfast_scanner PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME "VinFast Scanner"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.vinfast.diagnostics.scanner"
    MACOSX_BUNDLE_BUNDLE_VERSION "1.0.0"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0.0")
endif()

# -------------------------------------------------------------------
# Optional headless self-test (links the real DoIP/UDS stack, no Qt/curl).
# Build:  cmake -DBUILD_DOIP_SELFTEST=ON -S . -B build
# Run against tools/doip_simulator.py.
# -------------------------------------------------------------------
option(BUILD_DOIP_SELFTEST "Build the headless DoIP/UDS self-test CLI" OFF)
if(BUILD_DOIP_SELFTEST)
  add_executable(doip_selftest
    tools/doip_selftest.cpp
    src/Logger.cpp
    src/DoIPClient.cpp
    src/UDSClient.cpp
    src/VF8Data.cpp)
  target_include_directories(doip_selftest PRIVATE src)
  if(WIN32)
    target_link_libraries(doip_selftest PRIVATE ws2_32 iphlpapi)
  endif()
endif()
