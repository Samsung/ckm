/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 * @file        protocols.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by Central Key Manager.
 */

#include <protocols.h>

#include <dpl/serialization.h>

namespace CKM {

char const * const SERVICE_SOCKET_ECHO = "/tmp/.central-key-manager-echo.sock";
char const * const SERVICE_SOCKET_CKM_CONTROL = "/tmp/.central-key-manager-api-control.sock";
char const * const SERVICE_SOCKET_CKM_STORAGE = "/tmp/.central-key-manager-api-storage.sock";
char const * const SERVICE_SOCKET_OCSP = "/tmp/.central-key-manager-api-ocsp.sock";
char const * const LABEL_NAME_SEPARATOR = " ";

namespace {
const char* const DB_PERM_READ        = "R";
const char* const DB_PERM_READ_REMOVE = "RD";
}

const char* toDBPermission(Permission access_right_type) {
    switch(access_right_type) {
    case Permission::READ:          return DB_PERM_READ;
    case Permission::READ_REMOVE:   return DB_PERM_READ_REMOVE;
    default:
        // TODO
        throw 1;
    }
}

Permission toPermission(const std::string &input_DB_data) {
    if(input_DB_data == DB_PERM_READ_REMOVE)
        return Permission::READ_REMOVE;
    else if(input_DB_data == DB_PERM_READ)
        return Permission::READ;
    else
        return Permission::NONE;
}

} // namespace CKM

