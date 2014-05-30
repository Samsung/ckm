/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by Central
 *              Key Manager.
 */
#pragma once

namespace CKM {

extern char const * const SERVICE_SOCKET_ECHO;
extern char const * const SERVICE_SOCKET_CKM_CONTROL;
extern char const * const SERVICE_SOCKET_CKM_STORAGE;

enum class ControlCommand : int {
    UNLOCK_USER_KEY,
    LOCK_USER_KEY,
    REMOVE_USER_DATA,
    CHANGE_USER_PASSWORD,
    RESET_USER_PASSWORD
};

enum class DBDataType : int {
    UNKNOWN,
    KEY_RSA_PUBLIC,
    KEY_RSA_PRIVATE,
    KEY_ECDSA_PUBLIC,
    KEY_ECDSA_PRIVATE,
    KEY_AES,
    CERTIFICATE,
    BINARY_DATA
};

} // namespace CKM

