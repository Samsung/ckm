FIND_PACKAGE(Threads REQUIRED)
ADD_DEFINITIONS( "-DBOOST_TEST_DYN_LINK" )

SET(KEY_MANAGER_SRC_PATH ${PROJECT_SOURCE_DIR}/src)
SET(KEY_MANAGER_PATH ${PROJECT_SOURCE_DIR}/src/manager)

################################################################################


SET(KEY_MANAGER_TEST_MERGED_SRC ${PROJECT_SOURCE_DIR}/tests)

INCLUDE_DIRECTORIES(
    ${KEY_MANAGER_PATH}/dpl/db/include
    ${KEY_MANAGER_PATH}/dpl/core/include
    ${KEY_MANAGER_PATH}/dpl/log/include
    ${KEY_MANAGER_PATH}/sqlcipher
    ${KEY_MANAGER_PATH}/service
    ${KEY_MANAGER_PATH}/main
    ${KEY_MANAGER_PATH}/common/
    ${KEY_MANAGER_PATH}/client-async/
    ${KEY_MANAGER_SRC_PATH}/include
    ${KEY_MANAGER_TEST_MERGED_SRC}/
    )

SET(TEST_MERGED_SOURCES
    ${KEY_MANAGER_TEST_MERGED_SRC}/main.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/test_common.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/DBFixture.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/colour_log_formatter.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/test_db_crypto.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/test_sql.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/test-key-provider.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/test_safe-buffer.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/test_descriptor-set.cpp
    ${KEY_MANAGER_TEST_MERGED_SRC}/test_comm-manager.cpp
    ${KEY_MANAGER_PATH}/service/db-crypto.cpp
    ${KEY_MANAGER_PATH}/service/key-provider.cpp
    ${KEY_MANAGER_PATH}/client-async/descriptor-set.cpp
    ${KEY_MANAGER_PATH}/dpl/core/src/assert.cpp
    ${KEY_MANAGER_PATH}/dpl/core/src/colors.cpp
    ${KEY_MANAGER_PATH}/dpl/db/src/sql_connection.cpp
    ${KEY_MANAGER_PATH}/dpl/db/src/naive_synchronization_object.cpp
    ${KEY_MANAGER_PATH}/sqlcipher/sqlcipher.c
    )

ADD_EXECUTABLE(${TARGET_TEST_MERGED} ${TEST_MERGED_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_TEST_MERGED}
    ${TARGET_KEY_MANAGER_COMMON}
    ${CMAKE_THREAD_LIBS_INIT}
    boost_unit_test_framework
    -ldl
    )

INSTALL(TARGETS ${TARGET_TEST_MERGED} DESTINATION bin)
