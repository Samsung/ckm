SET(CKM_DB_TOOL "ckm_db_tool")
SET(KEY_MANAGER_PATH ${PROJECT_SOURCE_DIR}/src/manager)

PKG_CHECK_MODULES(CKM_DB_TOOL_DEP
    REQUIRED
    openssl
    libsmack
    libcrypto
    capi-base-common
    capi-system-info
    libxml-2.0
    cynara-client-async
    cynara-creds-socket
    )

FIND_PACKAGE(Threads REQUIRED)

INCLUDE_DIRECTORIES(
    ${CKM_DB_TOOL_DEP_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/tools/ckm_db_tool/
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

SET(CKM_DB_TOOL_SOURCES
    ${PROJECT_SOURCE_DIR}/tools/ckm_db_tool/ckm_db_tool.cpp
    ${PROJECT_SOURCE_DIR}/tools/ckm_db_tool/db-crypto-ext.cpp
    ${PROJECT_SOURCE_DIR}/tools/ckm_db_tool/ckm-logic-ext.cpp
    ${KEY_MANAGER_PATH}/initial-values/SWKeyFile.cpp

    ${KEY_MANAGER_PATH}/main/cynara.cpp
    ${KEY_MANAGER_PATH}/main/generic-socket-manager.cpp
    ${KEY_MANAGER_PATH}/main/socket-manager.cpp
    ${KEY_MANAGER_PATH}/main/smack-check.cpp
    ${KEY_MANAGER_PATH}/main/thread-service.cpp
    ${KEY_MANAGER_PATH}/main/socket-2-id.cpp
    ${KEY_MANAGER_PATH}/service/certificate-store.cpp
    ${KEY_MANAGER_PATH}/service/certificate-config.cpp
    ${KEY_MANAGER_PATH}/service/file-lock.cpp
    ${KEY_MANAGER_PATH}/service/access-control.cpp
    ${KEY_MANAGER_PATH}/service/ckm-logic.cpp
    ${KEY_MANAGER_PATH}/service/key-provider.cpp
    ${KEY_MANAGER_PATH}/service/crypto-logic.cpp
    ${KEY_MANAGER_PATH}/service/db-crypto.cpp
    ${KEY_MANAGER_PATH}/service/file-system.cpp
    ${KEY_MANAGER_PATH}/initial-values/parser.cpp
    ${KEY_MANAGER_PATH}/initial-values/BufferHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/CertHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/DataHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/KeyHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/PermissionHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/InitialValueHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/InitialValuesFile.cpp
    ${KEY_MANAGER_PATH}/initial-values/NoCharactersHandler.cpp
    ${KEY_MANAGER_PATH}/initial-values/xml-utils.cpp
    ${KEY_MANAGER_PATH}/dpl/core/src/assert.cpp
    ${KEY_MANAGER_PATH}/dpl/db/src/sql_connection.cpp
    ${KEY_MANAGER_PATH}/dpl/db/src/naive_synchronization_object.cpp
    ${KEY_MANAGER_PATH}/sqlcipher/sqlcipher.c
    ${KEY_MANAGER_PATH}/crypto/sw-backend/obj.cpp
    ${KEY_MANAGER_PATH}/crypto/sw-backend/internals.cpp
    ${KEY_MANAGER_PATH}/crypto/sw-backend/store.cpp
    ${KEY_MANAGER_PATH}/crypto/platform/decider.cpp
    ${KEY_MANAGER_PATH}/crypto/tz-backend/store.cpp
    ${KEY_MANAGER_PATH}/main/socket-2-id-mockup.cpp
    )

ADD_EXECUTABLE( ${CKM_DB_TOOL} ${CKM_DB_TOOL_SOURCES} )

TARGET_LINK_LIBRARIES(${CKM_DB_TOOL}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CKM_DB_TOOL_DEP_LIBRARIES}
    ${TARGET_KEY_MANAGER_COMMON}
    -ldl
    )

#place for output file
INSTALL(TARGETS ${CKM_DB_TOOL}
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
     )

