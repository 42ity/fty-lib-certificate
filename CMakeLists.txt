cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-lib-certificate
    VERSION 1.0.0
    DESCRIPTION "Library of helpers for ssl certificate"
)

##############################################################################################################
find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)
##############################################################################################################


##############################################################################################################
etn_target(static ${PROJECT_NAME}-static
    SOURCES
        src/libcert_certificate_config.cc
        src/libcert_certificate_X509.cc 
        src/libcert_crypto.cc
        src/libcert_csr_X509.cc 
        src/libcert_keys.cc 
        src/libcert_openssl_wrapper.cc
        src/libcert_pem_exportable.cc 
        src/libcert_public_key.cc 
    PUBLIC_INCLUDE_DIR
       include
    USES
        openssl
    PRIVATE
)
##############################################################################################################

# Create a target for the tests
etn_test_target(${PROJECT_NAME}-static
    SOURCES
        test/main.cpp
    USES
        ${PROJECT_NAME}-static
        openssl
)
##############################################################################################################
