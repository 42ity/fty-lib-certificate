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
# etn_target(exe ${PROJECT_NAME}-server
#     SOURCES
#         src/fty_alert_engine.cc
#         src/fty_alert_engine_server.cc
#     PUBLIC_INCLUDE_DIR
#         include
#     USES
#         ${PROJECT_NAME}-static
#         czmq
#         cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
#         fty_common
#         fty_common_logging
#         fty_proto
#         mlm
#         fty_shm
#         lua5.1
# )

# # install systemd config

# etn_configure_file(
#     src/${PROJECT_NAME}.service.in

#     TARGET      ${PROJECT_NAME}-server
#     DESTINATION /usr/lib/systemd/system/
# )

# #install config file

# etn_configure_file( 
#     src/conf/fty-alert-engine.cfg.in    
#     TARGET ${PROJECT_NAME}-server
#     DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/fty-alert-engine/"
# )

# install(
#     FILES ${PROJECT_SOURCE_DIR}/src/conf/fty-alert-engine-log.cfg
#     DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/fty/fty-alert-engine
# )

# install(
#     FILES ${PROJECT_SOURCE_DIR}/src/warranty.rule
#     DESTINATION ${CMAKE_INSTALL_PREFIX}/var/lib/fty/fty-alert-engine
# )

# set(AGENT_USER "bios")
# set(RULE_TEMPLATES_SHARE_DIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/bios/fty-autoconfig")

# FILE(GLOB rule_templates "${PROJECT_SOURCE_DIR}/src/rule_templates/*.rule")
# foreach(file ${rule_templates})
#   install(FILES ${file} DESTINATION ${RULE_TEMPLATES_SHARE_DIR}/)
# endforeach()
##############################################################################################################


# Create a target for the tests
# etn_test_target(${PROJECT_NAME}-server
#     SOURCES
#         src/fty_alert_engine_server.cc
#         test/main.cpp
#         test/engine_server_test.cpp
#     PUBLIC_INCLUDE_DIR
#         src
#     USES
#         ${PROJECT_NAME}-static
#         czmq
#         cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
#         fty_common
#         fty_common_logging
#         fty_proto
#         mlm
#         fty_shm
#         lua5.1
# )
# set(RULE_TEMPLATES_TEST "${CMAKE_CURRENT_BINARY_DIR}/test_rules/")

# FILE(GLOB rule_templates_test_f "${PROJECT_SOURCE_DIR}/test/templates/*.rule")
# foreach(file ${rule_templates_test_f})
#     file(COPY ${file} DESTINATION ${RULE_TEMPLATES_TEST}/templates)
# endforeach()

# FILE(GLOB rule_templates_test_s "${PROJECT_SOURCE_DIR}/test/testrules/*.rule")
# foreach(file ${rule_templates_test_s})
#     file(COPY ${file} DESTINATION ${RULE_TEMPLATES_TEST}/testrules)
# endforeach()


##############################################################################################################