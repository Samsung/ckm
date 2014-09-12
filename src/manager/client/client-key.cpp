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
 * @file        client-key.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Key - api implementation.
 */
#include <ckm/ckm-type.h>
#include <ckm/key-manager.h>

#include <dpl/log/log.h>

#include <key-rsa.h>

namespace CKM {

Key::Key()
  : m_impl(NULL)
{}

Key::Key(
    const RawBuffer &rawData,
    KeyType type,
    const std::string &password)
{
    switch (type) {
        case KeyType::KEY_RSA_PRIVATE:
            m_impl.reset(new KeyRSAPrivate(rawData, password));
            break;
        case KeyType::KEY_RSA_PUBLIC:
            m_impl.reset(new KeyRSAPublic(rawData, password));
            break;
        default:
            LogError("Key Type not implemented");
    }
}

Key::Key(const Key &second) {
    m_impl = second.m_impl;
}

Key& Key::operator=(const Key &second) {
    m_impl = second.m_impl;
    return *this;
}

Key::~Key(){}

bool Key::empty() const {
    if (m_impl)
        return m_impl->empty();
    return true;
}

KeyType Key::getType() const {
    if (m_impl)
        return m_impl->getType();
    return KeyType::KEY_NONE;
}

RawBuffer Key::getDER() const {
    if (m_impl)
        return m_impl->getDER();
    return RawBuffer();
}

GenericKey* Key::getImpl() const {
    if (m_impl)
        return m_impl.get();
    return NULL;
};


} // namespace CKM

