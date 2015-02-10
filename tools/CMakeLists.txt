SET(CKM_SO_LOADER "ckm_so_loader")

SET(CKM_SO_LOADER_SOURCES ${PROJECT_SOURCE_DIR}/tools/ckm_so_loader.cpp)

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
