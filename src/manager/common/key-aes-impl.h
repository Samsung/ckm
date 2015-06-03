/* Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        key-aes-impl.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       AES key.
 */
#pragma once

#include <ckm/ckm-type.h>
#include <ckm/ckm-key.h>
#include <symbol-visibility.h>

namespace CKM {

class COMMON_API KeyAESImpl : public Key {
public:
    explicit KeyAESImpl(const RawBuffer& buffer);

    virtual KeyType getType() const;
    virtual RawBuffer getDER() const;
    virtual int getSize() const;
    virtual bool empty() const;

protected:
    CKM::RawBuffer m_key;
};

} // namespace CKM
