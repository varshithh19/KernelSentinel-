cmake_minimum_required(VERSION 3.16)
project(kernelsentinel_collector C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(kernelsentinel_collector
    src/collector.c
)

if(WIN32)
    target_link_libraries(kernelsentinel_collector PRIVATE ws2_32)
else()
    target_link_libraries(kernelsentinel_collector PRIVATE pthread)
    find_library(LIBBPF_LIB bpf)
    find_library(LIBELF_LIB elf)
    if(LIBBPF_LIB)
        target_link_libraries(kernelsentinel_collector PRIVATE ${LIBBPF_LIB} ${LIBELF_LIB})
        target_compile_definitions(kernelsentinel_collector PRIVATE HAVE_LIBBPF=1)
    endif()
endif()
