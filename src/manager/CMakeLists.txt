PKG_CHECK_MODULES(COMMON_DEP
    REQUIRED
    dlog
    openssl
    db-util
    libsmack
    libcrypto
    )

SET(KEY_MANAGER_COMMON_VERSION_MAJOR 1)
SET(KEY_MANAGER_COMMON_VERSION ${KEY_MANAGER_COMMON_VERSION_MAJOR}.0.1)

SET(COMMON_PATH ${PROJECT_SOURCE_DIR}/src/manager)

SET(COMMON_SOURCES
    ${COMMON_PATH}/common/base64.cpp
    ${COMMON_PATH}/common/digest.cpp
    ${COMMON_PATH}/common/protocols.cpp
    ${COMMON_PATH}/common/message-buffer.cpp
    ${COMMON_PATH}/common/smack-check.cpp
    ${COMMON_PATH}/common/certificate-impl.cpp
    ${COMMON_PATH}/common/certificate-store.cpp
    ${COMMON_PATH}/common/key-impl.cpp
    ${COMMON_PATH}/dpl/log/src/abstract_log_provider.cpp
    ${COMMON_PATH}/dpl/log/src/dlog_log_provider.cpp
    ${COMMON_PATH}/dpl/log/src/log.cpp
    ${COMMON_PATH}/dpl/log/src/old_style_log_provider.cpp
    ${COMMON_PATH}/dpl/core/src/assert.cpp
    ${COMMON_PATH}/dpl/core/src/binary_queue.cpp
    ${COMMON_PATH}/dpl/core/src/colors.cpp
    ${COMMON_PATH}/dpl/core/src/exception.cpp
    ${COMMON_PATH}/dpl/core/src/noncopyable.cpp
    ${COMMON_PATH}/dpl/core/src/serialization.cpp
    ${COMMON_PATH}/dpl/core/src/singleton.cpp
    ${COMMON_PATH}/dpl/core/src/string.cpp
    ${COMMON_PATH}/dpl/core/src/errno_string.cpp
    ${COMMON_PATH}/dpl/db/src/sql_connection.cpp
    ${COMMON_PATH}/dpl/db/src/naive_synchronization_object.cpp
    ${COMMON_PATH}/sqlcipher/sqlcipher.c
    )

INCLUDE_DIRECTORIES(SYSTEM
    ${COMMON_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${COMMON_PATH}/common
    ${COMMON_PATH}/dpl/core/include
    ${COMMON_PATH}/dpl/log/include
    ${COMMON_PATH}/dpl/db/include
    ${COMMON_PATH}/sqlcipher
    ${COMMON_PATH}/service
    )

ADD_LIBRARY(${TARGET_KEY_MANAGER_COMMON} SHARED ${COMMON_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_KEY_MANAGER_COMMON}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
        SOVERSION ${KEY_MANAGER_COMMON_VERSION_MAJOR}
        VERSION ${KEY_MANAGER_COMMON_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_KEY_MANAGER_COMMON}
    ${COMMON_DEP_LIBRARIES}
    )

################################################################################

INSTALL(TARGETS ${TARGET_KEY_MANAGER_COMMON} DESTINATION ${LIB_INSTALL_DIR})
