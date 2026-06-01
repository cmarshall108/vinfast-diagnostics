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

# -------------------------------------------------------------------
# Qt6 (Widgets) - the GUI is modelled on TEXA IDC6: a dark, icon-driven
# navigator with compact pages and detail shown in relative popups.
# On macOS with Homebrew Qt, point CMake at the install prefix if needed:
#   cmake -B build -DCMAKE_PREFIX_PATH=$(brew --prefix qt)
# -------------------------------------------------------------------
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
add_executable(vinfast_scanner
  src/main.cpp
  src/Logger.cpp
  src/DoIPClient.cpp
  src/UDSClient.cpp
  src/VF8Data.cpp
  src/CloudData.cpp
  src/CloudClient.cpp
  src/Gui.cpp
)
target_include_directories(vinfast_scanner PRIVATE src)
target_link_libraries(vinfast_scanner PRIVATE Qt6::Widgets CURL::libcurl)

if(WIN32)
  target_link_libraries(vinfast_scanner PRIVATE ws2_32 iphlpapi)
endif()

if(APPLE)
  target_link_libraries(vinfast_scanner PRIVATE
    "-framework Cocoa" "-framework IOKit" "-framework CoreVideo")
endif()
