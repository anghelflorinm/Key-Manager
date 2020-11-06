cmake_minimum_required(VERSION 3.10)
project(Tema1)

set(CMAKE_CXX_STANDARD 14)

add_executable(key_manager key_manager.cpp macros.h message_crypt.h message_crypt.cpp)
add_executable(b b.cpp message_crypt.h message_crypt.cpp)
add_executable(a a.cpp keys_all.h keys_manager.h message_crypt.h message_crypt.cpp)

target_link_libraries(key_manager pthread crypto dl)
target_link_libraries(b pthread crypto dl)
target_link_libraries(a crypto dl)