/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file       smack-access.cpp
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <stdexcept>

#include <smack-access.h>

#include <sys/smack.h>

SmackAccess::SmackAccess() : m_handle(nullptr)
{
    if(0 != smack_accesses_new(&m_handle))
        throw std::runtime_error("smack_accesses_new failed");
}

void SmackAccess::add(
    const std::string &subject,
    const std::string &object,
    const std::string &rights)
{
    if(0 != smack_accesses_add(m_handle, subject.c_str(), object.c_str(), rights.c_str()))
        throw std::runtime_error("smack_accesses_add failed");
}

void SmackAccess::apply() {
    if(0 != smack_accesses_apply(m_handle))
        throw std::runtime_error("smack_accesses_apply failed");
}

SmackAccess::~SmackAccess() {
    if (m_handle)
        smack_accesses_free(m_handle);
}
