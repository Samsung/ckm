INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/key-manager.service
    ${CMAKE_SOURCE_DIR}/systemd/key-manager.target
    DESTINATION
    /usr/lib/systemd/system
)

