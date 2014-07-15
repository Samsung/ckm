INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/central-key-manager.service
    ${CMAKE_SOURCE_DIR}/systemd/central-key-manager.target
    ${CMAKE_SOURCE_DIR}/systemd/central-key-manager-api-control.socket
    ${CMAKE_SOURCE_DIR}/systemd/central-key-manager-api-storage.socket
    ${CMAKE_SOURCE_DIR}/systemd/central-key-manager-api-ocsp.socket
    ${CMAKE_SOURCE_DIR}/systemd/central-key-manager-echo.socket
    DESTINATION
    /usr/lib/systemd/system
)

