/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 * @file        client-error.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file contains example of key-manager client implementation
 */
#include <ckm/ckm-error.h>

#define ERRORDESCRIBE(name) case name: return #name

namespace CKM {
__attribute__ ((visibility ("default")))
const char * ErrorToString(int error) {
    switch(error) {
        ERRORDESCRIBE(KEY_MANAGER_API_SUCCESS);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_SOCKET);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_BAD_REQUEST);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_BAD_RESPONSE);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_SEND_FAILED);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_RECV_FAILED);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_AUTHENTICATION_FAILED);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_INPUT_PARAM);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_BUFFER_TOO_SMALL);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_OUT_OF_MEMORY);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_ACCESS_DENIED);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_SERVER_ERROR);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_DB_LOCKED);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_DB_BAD_REQUEST);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_DB_ERROR);
        ERRORDESCRIBE(KEY_MANAGER_API_ERROR_UNKNOWN);
    default:
        return "Error not defined";
    }
}

} // namespace CKM

