SET(CKM_SO_LOADER "ckm_so_loader")

SET(CKM_SO_LOADER_SOURCES ${PROJECT_SOURCE_DIR}/tools/ckm_so_loader.cpp)
SET(KEY_MANAGER_SRC_PATH ${PROJECT_SOURCE_DIR}/src)
ADD_EXECUTABLE( ${CKM_SO_LOADER} ${CKM_SO_LOADER_SOURCES} )

#linker directories
TARGET_LINK_LIBRARIES(${CKM_SO_LOADER} -ldl)

#place for output file
INSTALL(TARGETS ${CKM_SO_LOADER}
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
     )


SET(CKM_TOOL "ckm_tool")
SET(CKM_TOOL_SOURCES ${PROJECT_SOURCE_DIR}/tools/ckm_tool.cpp)

INCLUDE_DIRECTORIES(
    ${KEY_MANAGER_SRC_PATH}/include
    )

ADD_EXECUTABLE( ${CKM_TOOL} ${CKM_TOOL_SOURCES} )

#linker directories
TARGET_LINK_LIBRARIES(${CKM_TOOL}
    ${TARGET_KEY_MANAGER_CONTROL_CLIENT}
    )

#place for output file
INSTALL(TARGETS ${CKM_TOOL}
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
     )

ADD_SUBDIRECTORY(ckm_db_tool)