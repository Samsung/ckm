INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/key-manager.service
    ${CMAKE_SOURCE_DIR}/systemd/key-manager.target
    ${CMAKE_SOURCE_DIR}/systemd/key-manager-echo.socket
    DESTINATION
    /usr/lib/systemd/system
)

