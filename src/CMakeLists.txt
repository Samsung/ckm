PKG_CHECK_MODULES(KEY_MANAGER_DEP
    dlog
    openssl
    libsmack
    libsystemd-daemon
    REQUIRED
    )

SET(KEY_MANAGER_SRC_PATH ${PROJECT_SOURCE_DIR}/src)
SET(KEY_MANAGER_PATH ${PROJECT_SOURCE_DIR}/src/manager)

SET(KEY_MANAGER_SOURCES
    ${KEY_MANAGER_PATH}/main/key-manager-util.cpp
    ${KEY_MANAGER_PATH}/main/generic-socket-manager.cpp
    ${KEY_MANAGER_PATH}/main/socket-manager.cpp
    ${KEY_MANAGER_PATH}/main/key-manager-main.cpp
    ${KEY_MANAGER_PATH}/service/echo.cpp
    ${KEY_MANAGER_PATH}/service/ckm-service.cpp
    ${KEY_MANAGER_PATH}/service/ckm-logic.cpp
    ${KEY_MANAGER_PATH}/service/key-provider.cpp
    ${KEY_MANAGER_PATH}/service/ocsp.cpp
    ${KEY_MANAGER_PATH}/service/crypto-logic.cpp
    ${KEY_MANAGER_PATH}/service/CryptoService.cpp
    ${KEY_MANAGER_PATH}/service/file-system.cpp
    ${KEY_MANAGER_PATH}/service/db-crypto.cpp
    ${KEY_MANAGER_PATH}/service/ocsp-service.cpp
    ${KEY_MANAGER_PATH}/service/ocsp-logic.cpp
    )

SET_SOURCE_FILES_PROPERTIES(
    ${KEY_MANAGER_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden")

INCLUDE_DIRECTORIES(SYSTEM
    ${KEY_MANAGER_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${KEY_MANAGER_SRC_PATH}/include
    ${KEY_MANAGER_PATH}/main
    ${KEY_MANAGER_PATH}/common
    ${KEY_MANAGER_PATH}/service
    ${KEY_MANAGER_PATH}/sqlcipher
    ${KEY_MANAGER_PATH}/dpl/core/include
    ${KEY_MANAGER_PATH}/dpl/log/include
    ${KEY_MANAGER_PATH}/dpl/db/include
    )

ADD_EXECUTABLE(${TARGET_KEY_MANAGER} ${KEY_MANAGER_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_KEY_MANAGER}
    ${KEY_MANAGER_DEP_LIBRARIES}
    ${TARGET_KEY_MANAGER_COMMON}
    ${TARGET_KEY_MANAGER_KEY_PROVIDER}
    )



################################################################################

SET(KEY_MANAGER_CLIENT_VERSION_MAJOR 1)
SET(KEY_MANAGER_CLIENT_VERSION ${KEY_MANAGER_CLIENT_VERSION_MAJOR}.0.1)

SET(KEY_MANAGER_CLIENT_SRC_PATH ${KEY_MANAGER_PATH}/client)
SET(KEY_MANAGER_CLIENT_CAPI_SRC_PATH ${KEY_MANAGER_PATH}/client-capi)

INCLUDE_DIRECTORIES(
    ${KEY_MANAGER_PATH}/client
    ${KEY_MANAGER_PATH}/common
    ${KEY_MANAGER_PATH}/dpl/core/include
    ${KEY_MANAGER_PATH}/dpl/log/include
    )

SET(KEY_MANAGER_CLIENT_SOURCES
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-common.cpp
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-echo.cpp
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-error.cpp
    ${KEY_MANAGER_CLIENT_SRC_PATH}/client-manager-impl.cpp
    ${KEY_MANAGER_CLIENT_CAPI_SRC_PATH}/ckmc-type.cpp
    ${KEY_MANAGER_CLIENT_CAPI_SRC_PATH}/ckmc-error.cpp
    ${KEY_MANAGER_CLIENT_CAPI_SRC_PATH}/ckmc-manager.cpp
    )

ADD_LIBRARY(${TARGET_KEY_MANAGER_CLIENT} SHARED ${KEY_MANAGER_CLIENT_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_KEY_MANAGER_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
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
    ${KEY_MANAGER_PATH}/common
    ${KEY_MANAGER_PATH}/dpl/core/include
    ${KEY_MANAGER_PATH}/dpl/log/include
    )

SET(KEY_MANAGER_CONTROL_CLIENT_SOURCES
    ${KEY_MANAGER_CONTROL_CLIENT_SRC_PATH}/client-control.cpp
    ${KEY_MANAGER_CONTROL_CLIENT_SRC_PATH}/client-common.cpp
    ${KEY_MANAGER_CONTROL_CLIENT_CAPI_SRC_PATH}/ckmc-control.cpp
    )

ADD_LIBRARY(${TARGET_KEY_MANAGER_CONTROL_CLIENT} SHARED ${KEY_MANAGER_CONTROL_CLIENT_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_KEY_MANAGER_CONTROL_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
        SOVERSION ${KEY_MANAGER_CONTROL_CLIENT_VERSION_MAJOR}
        VERSION ${KEY_MANAGER_CONTROL_CLIENT_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_KEY_MANAGER_CONTROL_CLIENT}
    ${KEY_MANAGER_DEP_LIBRARIES}
    ${TARGET_KEY_MANAGER_COMMON}
    )

################################################################################
INSTALL(TARGETS ${TARGET_KEY_MANAGER_CLIENT} DESTINATION ${LIB_INSTALL_DIR})
INSTALL(TARGETS ${TARGET_KEY_MANAGER_CONTROL_CLIENT} DESTINATION ${LIB_INSTALL_DIR})

INSTALL(TARGETS ${TARGET_KEY_MANAGER} DESTINATION bin)


INSTALL(FILES
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-manager.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-certificate.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-control.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-error.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-echo.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-key.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-raw-buffer.h
    ${KEY_MANAGER_SRC_PATH}/include/ckm/ckm-type.h
    DESTINATION /usr/include/ckm/ckm
    )
INSTALL(FILES
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-manager.h
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-control.h
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-error.h
    ${KEY_MANAGER_SRC_PATH}/include/ckmc/ckmc-type.h
    DESTINATION /usr/include/ckm/ckmc
    )
################################################################################

ADD_SUBDIRECTORY(manager)
