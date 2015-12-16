# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author
# @brief
#

############################# Check minimum CMake version #####################

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT("key-manager")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

############################# compiler flags ##################################

SET(CMAKE_C_FLAGS_PROFILING    "-g -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_PROFILING  "-g -std=c++0x -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_DEBUG        "-g -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_DEBUG      "-g -std=c++0x -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_RELEASE      "-g -O2")
SET(CMAKE_CXX_FLAGS_RELEASE    "-g -std=c++0x -O2")
SET(CMAKE_C_FLAGS_CCOV         "-g -O2 --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       "-g -std=c++0x -O2 --coverage")

# If supported for the target machine, emit position-independent code,suitable
# for dynamic linking and avoiding any limit on the size of the global offset
# table. This option makes a difference on the m68k, PowerPC and SPARC.
# (BJ: our ARM too?)
ADD_DEFINITIONS("-fPIC")

# Set compiler warning flags
ADD_DEFINITIONS("-Werror")                      # Make all warnings into errors.
ADD_DEFINITIONS("-Wall")                        # Generate all warnings
ADD_DEFINITIONS("-Wextra")                      # Generate even more extra warnings

STRING(REGEX MATCH "([^.]*)" API_VERSION "${VERSION}")
ADD_DEFINITIONS("-DAPI_VERSION=\"$(API_VERSION)\"")
ADD_DEFINITIONS("-DSMACK_ENABLED")
ADD_DEFINITIONS("-DSQLCIPHER_HAS_CODEC")
ADD_DEFINITIONS("-DRUN_DIR=\"${RUN_DIR}\"")
ADD_DEFINITIONS("-DSERVICE_NAME=\"${SERVICE_NAME}\"")
ADD_DEFINITIONS("-DUSER_NAME=\"${USER_NAME}\"")
ADD_DEFINITIONS("-DGROUP_NAME=\"${GROUP_NAME}\"")
ADD_DEFINITIONS("-DSMACK_DOMAIN_NAME=\"${SMACK_DOMAIN_NAME}\"")

IF (CMAKE_BUILD_TYPE MATCHES "DEBUG")
    ADD_DEFINITIONS("-DTIZEN_DEBUG_ENABLE")
    ADD_DEFINITIONS("-DBUILD_TYPE_DEBUG")
ENDIF (CMAKE_BUILD_TYPE MATCHES "DEBUG")

IF (DEFINED SYSTEMD_ENV_FILE)
    ADD_DEFINITIONS(-DSYSTEMD_ENV_FILE="${SYSTEMD_ENV_FILE}")
ENDIF (DEFINED SYSTEMD_ENV_FILE)

SET(TARGET_KEY_MANAGER "key-manager")
SET(TARGET_KEY_MANAGER_CLIENT "key-manager-client")
SET(TARGET_KEY_MANAGER_CONTROL_CLIENT "key-manager-control-client")
SET(TARGET_KEY_MANAGER_COMMON "key-manager-common")
SET(TARGET_LISTENER "key-manager-listener")
SET(TARGET_PAM_KEY_MANAGER_PLUGIN "pam_key_manager_plugin")

SET(TARGET_TEST_MERGED "ckm-tests-internal")

INSTALL(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/data/scripts/230.key-manager-migrate-dkek.patch.sh
    ${CMAKE_CURRENT_BINARY_DIR}/data/scripts/231.key-manager-change-user.patch.sh
    DESTINATION /etc/opt/upgrade
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE)

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(build)
ADD_SUBDIRECTORY(systemd)
ADD_SUBDIRECTORY(tests)
ADD_SUBDIRECTORY(tools)
