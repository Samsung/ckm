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
 * @file        client-key-impl.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Key implementation.
 */
#pragma once

#include <dpl/serialization.h>

#include <ckm/ckm-type.h>
#include <ckm/key-manager.h>

namespace CKM {

class Key::KeyImpl : public ISerializable {
public:
    KeyImpl();
    KeyImpl(IStream &stream);
    KeyImpl(const RawData &data, KeyType type, const RawData &password);
    KeyImpl(const KeyImpl &);
    KeyImpl(KeyImpl &&);
    KeyImpl& operator=(const KeyImpl &);
    KeyImpl& operator=(KeyImpl &&);

    KeyType getType() const {
        return m_type;
    }

    RawData getKey() const {
        return m_key;
    }

    bool empty() const {
        return m_key.empty();
    }

    void Serialize(IStream &stream) const;

    virtual ~KeyImpl();
private:
    KeyType m_type;
    RawData m_key;
};

} // namespace CKM

