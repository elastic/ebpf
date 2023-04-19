set(LIBZ_SRC_DIR "${PROJECT_SOURCE_DIR}/contrib/libz")
set(LIBZ_BUILD_DIR "${PROJECT_BINARY_DIR}/contrib/libz")
set(LIBZ_LIB "${EBPF_INSTALL_DIR}/lib/libz.a")

ExternalProject_Add(
    libz-external
    BINARY_DIR ${LIBZ_BUILD_DIR}
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ${EBPF_EXT_ENV_FLAGS} /bin/sh -c "CFLAGS='-O3 -fPIE' ${LIBZ_SRC_DIR}/configure --static"
    BUILD_COMMAND ${EBPF_EXT_ENV_FLAGS} /bin/sh -c "make"
    INSTALL_COMMAND /bin/sh -c "make install prefix= DESTDIR=${EBPF_INSTALL_DIR}"
    BUILD_IN_SOURCE 0
    BUILD_BYPRODUCTS ${LIBZ_LIB}
)

add_library(libz STATIC IMPORTED GLOBAL)
set_property(TARGET libz PROPERTY IMPORTED_LOCATION "${LIBZ_LIB}")
set_property(TARGET libz PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${EBPF_INSTALL_DIR}/include")
add_dependencies(libz libz-external)
