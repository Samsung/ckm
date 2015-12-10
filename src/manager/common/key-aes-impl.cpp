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
 * @file        key-aes-impl.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       AES key implementation.
 */
#include <dpl/log/log.h>
#include <ckm/ckm-type.h>
#include <key-aes-impl.h>

namespace CKM {

KeyAESImpl::KeyAESImpl(const RawBuffer &buf) : m_key(buf)
{
    // buf stores bytes -> compare the bit sizes
    switch (buf.size() * 8) {
    case 128:
    case 192:
    case 256:
        break;

    default:
        throw std::invalid_argument("invalid AES key size");
    }
}

bool KeyAESImpl::empty() const
{
    return (getSize() == 0);
}

KeyType KeyAESImpl::getType() const
{
    return KeyType::KEY_AES;
}

RawBuffer KeyAESImpl::getDER() const
{
    return m_key;
}

int KeyAESImpl::getSize() const
{
    return m_key.size();
}

KeyShPtr Key::createAES(const RawBuffer &raw)
{
    try {
        KeyShPtr output = std::make_shared<KeyAESImpl>(raw);
        if (output->empty())
            output.reset();
        return output;
    } catch (const std::bad_alloc &) {
        LogDebug("Bad alloc during KeyAESImpl creation");
    } catch (const std::invalid_argument &e) {
        LogDebug(e.what());
    } catch (...) {
        LogError("Critical error: Unknown exception was caught during KeyAESImpl creation");
    }
    return KeyShPtr();
}

} // namespace CKM

