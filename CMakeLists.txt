cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-lib-certificate
    VERSION 1.0.0
    DESCRIPTION "Library of helpers for ssl certificate"
)

set(PROJECT_NAME_UNDERSCORE fty_lib_certificate)

##############################################################################################################
find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)
##############################################################################################################


##############################################################################################################
etn_target(shared ${PROJECT_NAME_UNDERSCORE}
    SOURCES
        src/libcert_certificate_X509.cc 
        src/libcert_crypto.cc
        src/libcert_csr_X509.cc 
        src/libcert_keys.cc 
        src/libcert_openssl_wrapper.cc
        src/libcert_public_key.cc 
    PUBLIC_INCLUDE_DIR
        public_include
    PUBLIC_HEADERS
        fty-lib-certificate.h
        libcert_certificate_X509.h
        libcert_certificate_config.h
        libcert_crypto.h
        libcert_csr_X509.h
        libcert_keys.h
        libcert_pem_exportable.h
        libcert_public_key.h
    USES
        openssl
)

set_target_properties(${PROJECT_NAME_UNDERSCORE} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

##############################################################################################################

# Create a target for the tests
etn_test_target(${PROJECT_NAME_UNDERSCORE}
    SOURCES
        test/main.cpp
        test/libcert_certificate_X509.cpp
        test/libcert_public_key.cpp 
        test/libcert_keys.cpp
        test/libcert_csr_X509.cpp
        test/libcert_certificate_config.cpp
    SUBDIR
        test
)
##############################################################################################################
