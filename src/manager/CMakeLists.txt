SET(KEY_MANAGER_COMMON_VERSION_MAJOR 1)
SET(KEY_MANAGER_COMMON_VERSION ${KEY_MANAGER_COMMON_VERSION_MAJOR}.0.1)

####################### set up dependency for common libraries #################

SET(CM_DEP
    openssl
    libcrypto)

IF(BUILD_WITH_DLOG)
    SET(CM_DEP ${CM_DEP} dlog)
ENDIF(BUILD_WITH_DLOG)

IF(BUILD_WITH_SYSTEMD)
    SET(CM_DEP ${CM_DEP} libsystemd-journal)
ENDIF(BUILD_WITH_SYSTEMD)

PKG_CHECK_MODULES(COMMON_DEP REQUIRED ${CM_DEP})

UNSET(CM_DEP)

######################### set up source files for common library ###############

SET(COMMON_PATH ${PROJECT_SOURCE_DIR}/src/manager)

SET(COMMON_SOURCES
    ${COMMON_PATH}/common/algo-param.cpp
    ${COMMON_PATH}/common/base64.cpp
    ${COMMON_PATH}/common/crypto-init.cpp
    ${COMMON_PATH}/common/data-type.cpp
    ${COMMON_PATH}/common/exception.cpp
    ${COMMON_PATH}/common/protocols.cpp
    ${COMMON_PATH}/common/message-buffer.cpp
    ${COMMON_PATH}/common/certificate-impl.cpp
    ${COMMON_PATH}/common/key-impl.cpp
    ${COMMON_PATH}/common/key-aes-impl.cpp
    ${COMMON_PATH}/common/pkcs12-impl.cpp
    ${COMMON_PATH}/common/log-setup.cpp
    ${COMMON_PATH}/dpl/log/src/abstract_log_provider.cpp
    ${COMMON_PATH}/dpl/log/src/log.cpp
    ${COMMON_PATH}/dpl/log/src/old_style_log_provider.cpp
    ${COMMON_PATH}/dpl/core/src/assert.cpp
    ${COMMON_PATH}/dpl/core/src/binary_queue.cpp
    ${COMMON_PATH}/dpl/core/src/colors.cpp
    ${COMMON_PATH}/dpl/core/src/exception.cpp
    ${COMMON_PATH}/dpl/core/src/serialization.cpp
    ${COMMON_PATH}/dpl/core/src/singleton.cpp
    ${COMMON_PATH}/dpl/core/src/errno_string.cpp
    )

IF(BUILD_WITH_DLOG)
    SET(COMMON_SOURCES ${COMMON_SOURCES} ${COMMON_PATH}/dpl/log/src/dlog_log_provider.cpp)
ENDIF(BUILD_WITH_DLOG)

IF(BUILD_WITH_SYSTEMD)
    SET(COMMON_SOURCES ${COMMON_SOURCES} ${COMMON_PATH}/dpl/log/src/journal_log_provider.cpp)
ENDIF(BUILD_WITH_SYSTEMD)

#################### set up environment values and compile  ####################

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
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${KEY_MANAGER_COMMON_VERSION_MAJOR}
        VERSION ${KEY_MANAGER_COMMON_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_KEY_MANAGER_COMMON}
    ${COMMON_DEP_LIBRARIES}
    )

################################# installation ################################

INSTALL(TARGETS ${TARGET_KEY_MANAGER_COMMON} DESTINATION ${LIB_DIR})

