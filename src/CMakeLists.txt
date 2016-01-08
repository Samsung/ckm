######################### set up dependences ##################################

SET(KM_DEP
    glib-2.0
    openssl
    libcrypto
    libxml-2.0
    cynara-client-async
    cynara-creds-socket)

IF(BUILD_WITH_SYSTEMD)
    SET(KM_DEP ${KM_DEP} libsystemd-daemon)
ENDIF(BUILD_WITH_SYSTEMD)

IF(BUILD_WITH_SMACK)
    SET(KM_DEP ${KM_DEP} libsmack)
ENDIF(BUILD_WITH_SMACK)

IF(BUILD_WITH_SECURITY_MANAGER)
    SET(KM_DEP ${KM_DEP} security-manager)
ENDIF(BUILD_WITH_SECURITY_MANAGER)

IF(BUILD_WITH_CAPI_SYSTEM_INFO)
    SET(KM_DEP ${KM_DEP} capi-system-info)
ENDIF(BUILD_WITH_CAPI_SYSTEM_INFO)

IF(BUILD_WITH_CAPI_BASE_COMMON)
    SET(KM_DEP ${KM_DEP} capi-base-common)
ENDIF(BUILD_WITH_CAPI_BASE_COMMON)

IF(BUILD_WITH_GLIB)
    SET(KM_DEP ${KM_DEP} glib-2.0 capi-appfw-package-manager)
ENDIF(BUILD_WITH_GLIB)

PKG_CHECK_MODULES(KEY_MANAGER_DEP REQUIRED ${KM_DEP})

UNSET(KM_DEP)

FIND_PACKAGE(Threads REQUIRED)

####################### set up sources ########################################

SET(KEY_MANAGER_SRC_PATH ${PROJECT_SOURCE_DIR}/src)
SET(KEY_MANAGER_PATH ${PROJECT_SOURCE_DIR}/src/manager)

SET(KEY_MANAGER_SOURCES
    ${KEY_MANAGER_PATH}/main/generic-socket-manager.cpp
    ${KEY_MANAGER_PATH}/main/socket-manager.cpp
    ${KEY_MANAGER_PATH}/main/key-manager-main.cpp
    ${KEY_MANAGER_PATH}/main/smack-check.cpp
    ${KEY_MANAGER_PATH}/main/thread-service.cpp
    ${KEY_MANAGER_PATH}/main/socket-2-id.cpp
    ${KEY_MANAGER_PATH}/service/certificate-store.cpp
    ${KEY_MANAGER_PATH}/service/certificate-config.cpp
    ${KEY_MANAGER_PATH}/service/file-lock.cpp
    ${KEY_MANAGER_PATH}/service/access-control.cpp
    ${KEY_MANAGER_PATH}/service/ckm-service.cpp
    ${KEY_MANAGER_PATH}/service/ckm-logic.cpp
    ${KEY_MANAGER_PATH}/service/key-provider.cpp
    ${KEY_MANAGER_PATH}/service/ocsp.cpp
    ${KEY_MANAGER_PATH}/service/crypto-logic.cpp
    ${KEY_MANAGER_PATH}/service/file-system.cpp
    ${KEY_MANAGER_PATH}/service/db-crypto.cpp
    ${KEY_MANAGER_PATH}/service/ocsp-service.cpp
    ${KEY_MANAGER_PATH}/service/ocsp-logic.cpp
    ${KEY_MANAGER_PATH}/service/encryption-service.cpp
    ${KEY_MANAGER_PATH}/service/encryption-logic.cpp
    ${KEY_MANAGER_PATH}/initial-values/parser.cpp
    ${KEY_MANAGER_PATH}/initial-values/BufferHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/CertHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/DataHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/KeyHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/PermissionHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/InitialValueHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/InitialValuesFile.cpp
    ${KEY_MANAGER_PATH}/initial-values/NoCharactersHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/SWKeyFile.cpp
    ${KEY_MANAGER_PATH}/initial-values/xml-utils.cpp
    ${KEY_MANAGER_PATH}/initial-values/initial-value-loader.cpp
    ${KEY_MANAGER_PATH}/dpl/core/src/assert.cpp
    ${KEY_MANAGER_PATH}/dpl/db/src/sql_connection.cpp
    ${KEY_MANAGER_PATH}/dpl/db/src/naive_synchronization_object.cpp
    ${KEY_MANAGER_PATH}/sqlcipher/sqlcipher.c
    ${KEY_MANAGER_PATH}/crypto/sw-backend/obj.cpp
    ${KEY_MANAGER_PATH}/crypto/sw-backend/internals.cpp
    ${KEY_MANAGER_PATH}/crypto/sw-backend/store.cpp
    ${KEY_MANAGER_PATH}/crypto/platform/decider.cpp
    ${KEY_MANAGER_PATH}/crypto/tz-backend/obj.cpp
    ${KEY_MANAGER_PATH}/crypto/tz-backend/store.cpp
    )

IF(BUILD_WITH_GLIB)
    SET(KEY_MANAGER_SOURCES
        ${KEY_MANAGER_SOURCES}
        ${KEY_MANAGER_PATH}/service/glib-service.cpp
        ${KEY_MANAGER_PATH}/service/glib-logic.cpp)
ENDIF(BUILD_WITH_GLIB)

IF(MOCKUP_SM OR NOT BUILD_WITH_SECURITY_MANAGER OR NOT BUILD_WITH_CYNARA)
    IF (CMAKE_BUILD_TYPE MATCHES "RELEASE")
        MESSAGE(FATAL_ERROR "You cannot compile release version with SECURITY MOCKUPS!")
    ENDIF (CMAKE_BUILD_TYPE MATCHES "RELEASE")
    MESSAGE("USING MOCKUPS INSTEAD SECURITY MODULES (SECURITY MANAGER AND CYNARA)")
    SET(KEY_MANAGER_SOURCES
        ${KEY_MANAGER_SOURCES}
        ${KEY_MANAGER_PATH}/main/cynara-mockup.cpp
        ${KEY_MANAGER_PATH}/main/socket-2-id-mockup.cpp)
ELSE(MOCKUP_SM OR NOT BUILD_WITH_SECURITY_MANAGER OR NOT BUILD_WITH_CYNARA)
    SET(KEY_MANAGER_SOURCES
        ${KEY_MANAGER_SOURCES}
        ${KEY_MANAGER_PATH}/main/socket-2-id-wrapper.cpp
        ${KEY_MANAGER_PATH}/main/cynara.cpp)
ENDIF(MOCKUP_SM OR NOT BUILD_WITH_SECURITY_MANAGER OR NOT BUILD_WITH_CYNARA)

############################# let's compile ###################################

# -fPIE and -pie flag is added for ASLR
SET_SOURCE_FILES_PROPERTIES(
    ${KEY_MANAGER_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE")

INCLUDE_DIRECTORIES(SYSTEM ${KEY_MANAGER_DEP_INCLUDE_DIRS})

IF(BUILD_WITH_CAPI_BASE_COMMON)
    INCLUDE_DIRECTORIES(${KEY_MANAGER_SRC_PATH}/include-tizen)
ELSE(BUILD_WITH_CAPI_BASE_COMMON)
    INCLUDE_DIRECTORIES(${KEY_MANAGER_SRC_PATH}/include-ubuntu)
ENDIF(BUILD_WITH_CAPI_BASE_COMMON)

INCLUDE_DIRECTORIES(
    ${KEY_MANAGER_SRC_PATH}/include
    ${KEY_MANAGER_PATH}/main
    ${KEY_MANAGER_PATH}/common
    ${KEY_MANAGER_PATH}/service
    ${KEY_MANAGER_PATH}/initial-values
    ${KEY_MANAGER_PATH}/sqlcipher
    ${KEY_MANAGER_PATH}/dpl/core/include
    ${KEY_MANAGER_PATH}/dpl/log/include
    ${KEY_MANAGER_PATH}/dpl/db/include
    ${KEY_MANAGER_PATH}/crypto
    )

LINK_DIRECTORIES(${KEY_MANAGER_DEP_LIBRARY_DIRS})

ADD_EXECUTABLE(${TARGET_KEY_MANAGER} ${KEY_MANAGER_SOURCES})

# pie flag is added for ASLR
TARGET_LINK_LIBRARIES(${TARGET_KEY_MANAGER}
    ${CMAKE_THREAD_LIBS_INIT}
    ${KEY_MANAGER_DEP_LIBRARIES}
    ${TARGET_KEY_MANAGER_COMMON}
    -ldl -pie
    )

################################################################################

SET(KEY_MANAGER_CLIENT_VERSION_MAJOR 1)
SET(KEY_MANAGER_CLIENT_VERSION ${KEY_MANAGER_CLIENT_VERSION_MAJOR}.0.1)

SET(KEY_MANAGER_CLIENT_SRC_PATH ${KEY_MANAGER_PATH}/client)
SET(KEY_MANAGER_CLIENT_ASYNC_SRC_PATH ${KEY_MANAGER_PATH}/client-async)
SET(KEY_MANAGER_CLIENT_CAPI_SRC_PATH ${KEY_MANAGER_PATH}/client-capi)

INCLUDE_DIRECTORIES(
    ${KEY_MANAGER_PATH}/client
    ${KEY_MANAGER_PATH}/client-async
    ${KEY_MANAGER_PATH}/client-capi
    ${KEY_MANAGER_PATH}/common
    ${KEY_MANAGER_PATH}/dpl/core/include
    ${KEY_MANAGER_PATH}/dpl/log/include
    )

SET(KEY_MANAGER_CLIENT_SOURCES
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-common.cpp
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-error.cpp
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-manager.cpp
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-manager-impl.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/client-manager-async.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/client-manager-async-impl.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/connection-thread.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/async-request.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/service.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/storage-receiver.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/ocsp-receiver.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/encryption-receiver.cpp
    ${KEY_MANAGER_CLIENT_ASYNC_SRC_PATH}/descriptor-set.cpp
    ${KEY_MANAGER_CLIENT_CAPI_SRC_PATH}/ckmc-type.cpp
    ${KEY_MANAGER_CLIENT_CAPI_SRC_PATH}/ckmc-error.cpp
    ${KEY_MANAGER_CLIENT_CAPI_SRC_PATH}/ckmc-manager.cpp
    ${KEY_MANAGER_CLIENT_CAPI_SRC_PATH}/ckmc-type-converter.cpp
    )

ADD_LIBRARY(${TARGET_KEY_MANAGER_CLIENT} SHARED ${KEY_MANAGER_CLIENT_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_KEY_MANAGER_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${KEY_MANAGER_CLIENT_VERSION_MAJOR}
        VERSION ${KEY_MANAGER_CLIENT_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_KEY_MANAGER_CLIENT}
    ${KEY_MANAGER_DEP_LIBRARIES}
    ${TARGET_KEY_MANAGER_COMMON}
    )

################################################################################

SET(KEY_MANAGER_CONTROL_CLIENT_VERSION_MAJOR 1)
SET(KEY_MANAGER_CONTROL_CLIENT_VERSION ${KEY_MANAGER_CONTROL_CLIENT_VERSION_MAJOR}.0.1)

SET(KEY_MANAGER_CONTROL_CLIENT_SRC_PATH ${KEY_MANAGER_PATH}/client)
SET(KEY_MANAGER_CONTROL_CLIENT_CAPI_SRC_PATH ${KEY_MANAGER_PATH}/client-capi)

INCLUDE_DIRECTORIES(
    ${KEY_MANAGER_PATH}/client
    ${KEY_MANAGER_PATH}/client-capi
    ${KEY_MANAGER_PATH}/common
    ${KEY_MANAGER_PATH}/dpl/core/include
    ${KEY_MANAGER_PATH}/dpl/log/include
    )

SET(KEY_MANAGER_CONTROL_CLIENT_SOURCES
    ${KEY_MANAGER_CONTROL_CLIENT_SRC_PATH}/client-control.cpp
    ${KEY_MANAGER_CONTROL_CLIENT_SRC_PATH}/client-common.cpp
    ${KEY_MANAGER_CONTROL_CLIENT_CAPI_SRC_PATH}/ckmc-control.cpp
    ${KEY_MANAGER_CONTROL_CLIENT_CAPI_SRC_PATH}/ckmc-type-converter.cpp
    )

ADD_LIBRARY(${TARGET_KEY_MANAGER_CONTROL_CLIENT} SHARED ${KEY_MANAGER_CONTROL_CLIENT_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_KEY_MANAGER_CONTROL_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${KEY_MANAGER_CONTROL_CLIENT_VERSION_MAJOR}
        VERSION ${KEY_MANAGER_CONTROL_CLIENT_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_KEY_MANAGER_CONTROL_CLIENT}
    ${KEY_MANAGER_DEP_LIBRARIES}
    ${TARGET_KEY_MANAGER_COMMON}
    )

################################################################################
INSTALL(TARGETS ${TARGET_KEY_MANAGER_CLIENT} DESTINATION ${LIB_DIR})
INSTALL(TARGETS ${TARGET_KEY_MANAGER_CONTROL_CLIENT} DESTINATION ${LIB_DIR})

INSTALL(TARGETS ${TARGET_KEY_MANAGER} DESTINATION ${BIN_DIR})

INSTALL(FILES
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-manager.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-manager-async.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-certificate.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-control.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-error.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-key.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-password.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-pkcs12.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-raw-buffer.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-type.h
    DESTINATION ${INCLUDE_DIR}/ckm/ckm)

INSTALL(FILES
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-manager.h
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-control.h
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-error.h
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-type.h
    DESTINATION ${INCLUDE_DIR}/ckm/ckmc)

IF(BUILD_WITH_CAPI_BASE_COMMON)
    INSTALL(FILES ${KEY_MANAGER_SRC_PATH}/include-tizen/ckmc/ckmc-platform-codes.h DESTINATION ${INCLUDE_DIR}/ckm/ckmc)
ELSE(BUILD_WITH_CAPI_BASE_COMMON)
    INSTALL(FILES ${KEY_MANAGER_SRC_PATH}/include-ubuntu/ckmc/ckmc-platform-codes.h DESTINATION ${INCLUDE_DIR}/ckm/ckmc)
ENDIF(BUILD_WITH_CAPI_BASE_COMMON)
################################################################################

ADD_SUBDIRECTORY(manager)
IF(BUILD_ON_TIZEN)
    ADD_SUBDIRECTORY(pam_plugin)
ENDIF(BUILD_ON_TIZEN)
