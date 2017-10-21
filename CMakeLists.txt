cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

include(GNUInstallDirs)

project(libscrypt VERSION 1.21 LANGUAGES C)

enable_testing()

add_library(scrypt
    b64.c
    crypto-mcf.c
    crypto-scrypt-saltgen.c
    crypto_scrypt-check.c
    crypto_scrypt-hash.c
    crypto_scrypt-hexconvert.c
    crypto_scrypt-nosse.c
    sha256.c
    slowequals.c)

set_target_properties(scrypt PROPERTIES COMPILE_FLAGS "-Wall -fstack-protector -D_FORTIFY_SOURCE=2")

install(TARGETS scrypt EXPORT ScryptConfig
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR})

install(EXPORT ScryptConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/libscrypt/cmake)
install(FILES "libscrypt.h" DESTINATION include/libscrypt)

export(TARGETS scrypt FILE ScryptConfig.cmake)

add_executable(reference main.c)

target_link_libraries(reference scrypt)

add_test(reference reference)
