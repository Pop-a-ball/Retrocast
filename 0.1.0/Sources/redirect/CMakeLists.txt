cmake_minimum_required(VERSION 3.15)
project(project LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_LIBTINS "Enable libtins-based reassembly" OFF)

add_executable(windivert_redirect src/windivert_redirect.cpp)

option(ENABLE_REDIRECT "Build the WinDivert redirect example" OFF)

target_include_directories(windivert_redirect PRIVATE include)

# Link WinDivert redirect against Windows socket libraries
if(WIN32)
    # Link against Windows socket libraries. Use ws2_32 (Winsock) and iphlpapi.
    target_link_libraries(windivert_redirect PRIVATE ws2_32 iphlpapi)
endif()

if(ENABLE_LIBTINS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBTINS REQUIRED libtins)
    include_directories(${LIBTINS_INCLUDE_DIRS})
    target_link_libraries(project PRIVATE ${LIBTINS_LIBRARIES})
    target_compile_definitions(project PRIVATE USE_LIBTINS)
endif()

# Link against the scanner cdylib when available
# On Windows, provide path to scanner.dll import lib or use LoadLibrary dynamically.

# Example: link_directories("${CMAKE_SOURCE_DIR}/../scanner/target/debug")
# target_link_libraries(project PRIVATE scanner)