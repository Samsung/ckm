/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file    ckm-manager.h
 * @version 1.0
 * @brief   This file contains APIs of the Central Key Manager
*/
#ifndef KEY_MANAGER_ECHO_H
#define KEY_MANAGER_ECHO_H
/*
 * This function was created mainly for testing ckm-manager client/service
 * proper behaviour. It sends a message and returns message from service,
 * which should be a pure echo.
 *
 * \param[in] Message for service
 * \param[out] Response from service
 *
 * \return CKM_API_ERROR_INPUT_PARAM when trying to pass NULL message
 * \return CKM_API_SUCCESS on success
 */
namespace CKM {

int key_manager_echo(const char* echo, char** oche);

} // namespace CKM

#endif

