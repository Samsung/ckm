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
 * @file       smack-access.h
 * @author     Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <string>

struct smack_accesses;

class SmackAccess {
public:
    SmackAccess();
    SmackAccess(const SmackAccess &second) = delete;
    SmackAccess& operator=(const SmackAccess &second) = delete;

    void add(const std::string &subject,
             const std::string &object,
             const std::string &rights);
    void apply();
    virtual ~SmackAccess();
private:
    struct smack_accesses *m_handle;
};
