cmake_minimum_required(VERSION 3.16.3)
project(lab8 C)

set(CMAKE_C_STANDARD 11)

add_executable(lab8 server.c client.c utils.h)

target_link_libraries(lab8 rt)

add_compile_options(-Wall -fsanitize=address,undefined -ansi -pedantic)