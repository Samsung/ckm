# Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# @file        CMakeLists.txt
# @author      Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
# @brief
#

INCLUDE(FindPkgConfig)

# common encryption scheme library
PKG_CHECK_MODULES(ENCRYPTION_SCHEME_DEP
    libsmack
    REQUIRED)

SET(ENCRYPTION_SCHEME_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/smack-access.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/scheme-test.cpp
)

INCLUDE_DIRECTORIES(SYSTEM ${ENCRYPTION_SCHEME_DEP_INCLUDE_DIRS})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR} )

ADD_LIBRARY(${TARGET_ENCRYPTION_SCHEME_COMMON} STATIC ${ENCRYPTION_SCHEME_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_ENCRYPTION_SCHEME_COMMON}
    ${ENCRYPTION_SCHEME_DEP_LIBRARIES}
    ${TARGET_KEY_MANAGER_CLIENT}
    ${TARGET_KEY_MANAGER_CONTROL_CLIENT}
)

INSTALL(TARGETS ${TARGET_ENCRYPTION_SCHEME_COMMON} DESTINATION ${LIB_INSTALL_DIR})



# binary for filling db
SET(TARGET_CKM_GENERATOR "ckm_generate_db")

SET(GENERATOR_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/generate-db.cpp
)

ADD_EXECUTABLE(${TARGET_CKM_GENERATOR} ${GENERATOR_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_CKM_GENERATOR}
    ${TARGET_ENCRYPTION_SCHEME_COMMON}
)

INSTALL(TARGETS ${TARGET_CKM_GENERATOR} DESTINATION bin)


INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/encryption-scheme.p12 DESTINATION /usr/share/ckm-db-test)