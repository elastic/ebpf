string(JOIN " " EBPF_EXT_ENV_FLAGS ${EBPF_EXTERNAL_ENV_FLAGS})

if (NOT STRIP)
    set(STRIP strip)
endif()

if (NOT EBPF_INSTALL_DIR)
    set(EBPF_INSTALL_DIR "${PROJECT_BINARY_DIR}/package")
endif()

file(MAKE_DIRECTORY "${EBPF_INSTALL_DIR}/include")

function(ebpf_get_includes OUT_VAR TARGET)
    get_target_property(DIRS_LIST ${TARGET} INTERFACE_INCLUDE_DIRECTORIES)
    foreach(IDIR ${DIRS_LIST})
        set(MVAR ${MVAR} "-I${IDIR}")
    endforeach()
    set(${OUT_VAR} ${MVAR} PARENT_SCOPE)
endfunction()

function(ebpf_static_library target)
    set(options OPTIONAL INSTALL)
    set(multiValueArgs SOURCES LINK DEPENDENCIES PUBLIC_HEADERS)

    cmake_parse_arguments(EBPF_LIB "${options}" ""
        "${multiValueArgs}" ${ARGN})

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/public-headers)

    add_library(${target} STATIC ${EBPF_LIB_SOURCES})

    if (EBPF_LIB_LINK)
        target_link_libraries(${target} ${EBPF_LIB_LINK})
    endif()

    if (EBPF_LIB_DEPENDENCIES)
        add_dependencies(${target} ${EBPF_LIB_DEPENDENCIES})
    endif()

    foreach(HDR ${EBPF_LIB_PUBLIC_HEADERS})
        configure_file(${HDR} ${CMAKE_CURRENT_BINARY_DIR}/public-headers/${HDR} COPYONLY)
    endforeach()

    set_property(TARGET ${target} PROPERTY PUBLIC_HEADER
        ${EBPF_LIB_PUBLIC_HEADERS}
    )

    target_include_directories(${target} INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/public-headers)

    if (EBPF_LIB_INSTALL)
        install(TARGETS
            ${target}
            LIBRARY DESTINATION ${EBPF_INSTALL_DIR}/lib
            PUBLIC_HEADER DESTINATION ${EBPF_INSTALL_DIR}/include
        )
    endif()
endfunction()

function(ebpf_static_binary target)
    set(options OPTIONAL INSTALL)
    set(multiValueArgs SOURCES LINK DEPENDENCIES)

    cmake_parse_arguments(EBPF_BIN "${options}" ""
        "${multiValueArgs}" ${ARGN})

    add_executable(${target} ${EBPF_BIN_SOURCES})

    if (EBPF_BIN_LINK)
        target_link_libraries(${target} ${EBPF_BIN_LINK})
    endif()

    if (EBPF_BIN_DEPENDENCIES)
        add_dependencies(${target} ${EBPF_BIN_DEPENDENCIES})
    endif()

    target_link_options(${target} PUBLIC -static -static-libstdc++)

    if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
        add_custom_command(
            TARGET ${target}
            POST_BUILD
            COMMAND ${STRIP} ${CMAKE_CURRENT_BINARY_DIR}/${target}
            VERBATIM
        )
    endif()

    if (EBPF_BIN_INSTALL)
        install(TARGETS
            ${target}
            RUNTIME DESTINATION ${EBPF_INSTALL_DIR}/bin
        )
    endif()
endfunction()