/*
 *  Copyright (c) 2014 Samsung Electronics Co.
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
 * @file        ckm-key.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Main header file for client library.
 */
#pragma once

#include <ckm/ckm-type.h>

namespace CKM {

class Key;
typedef std::shared_ptr<Key> KeyShPtr;

class KEY_MANAGER_API Key {
public:
    virtual bool empty() const = 0;
    virtual KeyType getType() const = 0;
    virtual int getSize() const = 0;
    virtual RawBuffer getDER() const = 0;
    virtual ~Key() {}

    static KeyShPtr create(
        const RawBuffer &rawBuffer,
        const Password &password = Password());

    static KeyShPtr createAES(
        const RawBuffer &rawBuffer);
};

} // namespace CKM

