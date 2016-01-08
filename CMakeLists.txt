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
SET(VERSION 0.1.18 CACHE STRING "key-manager main version")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)
INCLUDE(GNUInstallDirs)

############################# optional packages ###############################

PKG_CHECK_MODULES(SYSTEMD_DEP
    QUIET
    libsystemd-daemon
    libsystemd-journal)

IF(SYSTEMD_DEP_FOUND)
    SET(BUILD_WITH_SYSTEMD ON)
    ADD_DEFINITIONS("-DBUILD_WITH_SYSTEMD")
ENDIF(SYSTEMD_DEP_FOUND)

PKG_CHECK_MODULES(SMACK_DEP
    QUIET
    libsmack)

IF(SMACK_DEP_FOUND)
    SET(BUILD_WITH_SMACK ON)
    ADD_DEFINITIONS("-DBUILD_WITH_SMACK")
ENDIF(SMACK_DEP_FOUND)

PKG_CHECK_MODULES(SECURITY_MANAGER_DEP
    QUIET
    security-manager)

IF(SECURITY_MANAGER_DEP_FOUND)
    SET(BUILD_WITH_SECURITY_MANAGER ON)
    ADD_DEFINITIONS("-DBUILD_WITH_SECURITY_MANAGER")
ENDIF(SECURITY_MANAGER_DEP_FOUND)

PKG_CHECK_MODULES(CAPI_SYSTEM_INFO_DEP
    QUIET
    capi-system-info)

IF(CAPI_SYSTEM_INFO_DEP_FOUND)
    SET(BUILD_WITH_CAPI_SYSTEM_INFO ON)
    ADD_DEFINITIONS("-DBUILD_WITH_CAPI_SYSTEM_INFO")
ENDIF(CAPI_SYSTEM_INFO_DEP_FOUND)

PKG_CHECK_MODULES(CAPI_BASE_COMMON_DEP
    QUIET
    capi-base-common)

IF(CAPI_BASE_COMMON_DEP_FOUND)
    SET(BUILD_WITH_CAPI_BASE_COMMON ON)
    SET(BUILD_ON_TIZEN ON)
    ADD_DEFINITIONS("-DBUILD_WITH_CAPI_BASE_COMMON")
    ADD_DEFINITIONS("-DBUILD_ON_TIZEN")
ENDIF(CAPI_BASE_COMMON_DEP_FOUND)

PKG_CHECK_MODULES(DLOG_DEP
    QUIET
    dlog)

IF(DLOG_DEP_FOUND)
    SET(BUILD_WITH_DLOG ON)
    ADD_DEFINITIONS("-DBUILD_WITH_DLOG")
ENDIF(DLOG_DEP_FOUND)

PKG_CHECK_MODULES(GLIB_DEP
    QUIET
    glib-2.0
    capi-appfw-package-manager)

IF(GLIB_DEP_FOUND)
    SET(BUILD_WITH_GLIB ON)
    ADD_DEFINITIONS("-DBUILD_WITH_GLIB")
ENDIF(GLIB_DEP_FOUND)

############################# compiler flags ##################################

#SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-std=c++0x")

SET(CMAKE_C_FLAGS_PROFILING    "-g -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_PROFILING  "-g -std=c++0x -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_DEBUG        "-g -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_DEBUG      "-g -std=c++0x -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_RELEASE      "-g -O2")
SET(CMAKE_CXX_FLAGS_RELEASE    "-g -std=c++0x -O2")
SET(CMAKE_C_FLAGS_CCOV         "-g -O2 --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       "-g -std=c++0x -O2 --coverage")

############################# directories #####################################

SET(LIB_DIR
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
    CACHE PATH
    "Intall shared library directory")

SET(BIN_DIR
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}"
    CACHE PATH
    "User executable directory")

SET(SBIN_DIR
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SBINDIR}"
    CACHE PATH
    "Super user executable directory")

SET(SYS_CONFIG_DIR
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}"
    CACHE PATH
    "Read-only single-machine data directory")

SET(INCLUDE_DIR
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}"
    CACHE PATH
    "Header files directory")

SET(LOCAL_STATE_DIR
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LOCALSTATEDIR}"
    CACHE PATH
    "Modifiable single-machine data directory")

SET(DATA_ROOT_DIR
    "${CMAKE_INSTALL_PREFIX}/share"
    CACHE PATH
    "Read-only architecture-independent data root directory")

SET(SYSTEMD_UNIT_DIR
    "${CMAKE_INSTALL_PREFIX}/lib/systemd/system"
    CACHE PATH
    "Systemd system unit file directory")

SET(RUN_DIR
    "${CMAKE_INSTALL_PREFIX}/run"
    CACHE PATH
    "Running system information directory")

SET(UPGRADE_DIR
    "${CMAKE_INSTALL_PREFIX}/etc/opt/upgrade"
    CACHE PATH
    "Tizen directory with upgrade scripts")

ADD_DEFINITIONS("-DLIB_DIR=\"${LIB_DIR}\"")
ADD_DEFINITIONS("-DBIN_DIR=\"${BIN_DIR}\"")
ADD_DEFINITIONS("-DSBIN_DIR=\"${SBIN_DIR}\"")
ADD_DEFINITIONS("-DSYS_CONFIG_DIR=\"${SYS_CONFIG_DIR}\"")
ADD_DEFINITIONS("-DINCLUDE_DIR=\"${INCLUDE_DIR}\"")
ADD_DEFINITIONS("-DLOCAL_STATE_DIR=\"${LOCAL_STATE_DIR}\"")
ADD_DEFINITIONS("-DDATA_ROOT_DIR=\"${DATA_ROOT_DIR}\"")
ADD_DEFINITIONS("-DSYSTEMD_UNIT_DIR=\"${SYSTEMD_UNIT_DIR}\"")
ADD_DEFINITIONS("-DRUN_DIR=\"${RUN_DIR}\"")
ADD_DEFINITIONS("-DUPGRADE_DIR=\"${UPGRADE_DIR}\"")

############################# definitions #####################################
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
ADD_DEFINITIONS("-DSERVICE_NAME=\"${SERVICE_NAME}\"")
ADD_DEFINITIONS("-DUSER_NAME=\"${USER_NAME}\"")
ADD_DEFINITIONS("-DGROUP_NAME=\"${GROUP_NAME}\"")
ADD_DEFINITIONS("-DSMACK_DOMAIN_NAME=\"${SMACK_DOMAIN_NAME}\"")
ADD_DEFINITIONS("-DRW_DATA_DIR=\"${RW_DATA_DIR}\"")
ADD_DEFINITIONS("-DRO_DATA_DIR=\"${RO_DATA_DIR}\"")
ADD_DEFINITIONS("-DINITIAL_VALUES_DIR=\"${INITIAL_VALUES_DIR}\"")

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

CONFIGURE_FILE(packaging/key-manager.manifest.in key-manager.manifest @ONLY)

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(build)

IF(BUILD_WITH_SYSTEMD)
    ADD_SUBDIRECTORY(data/scripts)
    ADD_SUBDIRECTORY(systemd)
ENDIF(BUILD_WITH_SYSTEMD)

IF(BUILD_ON_TIZEN)
    ADD_SUBDIRECTORY(tests)
    ADD_SUBDIRECTORY(tools)
ENDIF(BUILD_ON_TIZEN)
