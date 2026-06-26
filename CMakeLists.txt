cmake_minimum_required(VERSION 3.10)
project(axon VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2")

set(SOURCES
    core/source/main.c
    core/source/constants.c
    core/source/context.c
    core/source/handshake.c
    core/source/record.c
    core/source/state.c
    crypto/source/aes_gcm.c
    crypto/source/chacha20.c
    crypto/source/x25519.c
    crypto/source/hkdf.c
    crypto/source/sha256.c
    crypto/source/constant.c
    parser/source/asn1.c
    parser/source/x509.c
    memory/source/secure.c
    memory/source/pool.c
    utils/source/bytes.c
    utils/source/log.c
)

set(HEADERS
    core/include/axon_engine.h
    core/include/constants.h
    core/include/context.h
    core/include/handshake.h
    core/include/record.h
    core/include/state.h
    crypto/include/aes_gcm.h
    crypto/include/chacha20.h
    crypto/include/x25519.h
    crypto/include/hkdf.h
    crypto/include/sha256.h
    crypto/include/constant.h
    parser/include/asn1.h
    parser/include/x509.h
    memory/include/secure.h
    memory/include/pool.h
    utils/include/bytes.h
    utils/include/log.h
)

add_library(axon_static STATIC ${SOURCES})
add_library(axon_shared SHARED ${SOURCES})

add_executable(axon-engine core/source/main.c)
target_link_libraries(axon-engine axon_static)

install(TARGETS axon_static axon_shared DESTINATION lib)
install(FILES ${HEADERS} DESTINATION include/axon)

enable_testing()
add_executable(test_handshake tests/c/test_handshake.c)
target_link_libraries(test_handshake axon_static)
add_test(NAME HandshakeTest COMMAND test_handshake)

add_executable(test_crypto tests/c/test_crypto.c)
target_link_libraries(test_crypto axon_static)
add_test(NAME CryptoTests COMMAND test_crypto)

add_executable(test_asn1 tests/c/test_asn1.c)
target_link_libraries(test_asn1 axon_static)
add_test(NAME ASN1Tests COMMAND test_asn1)
