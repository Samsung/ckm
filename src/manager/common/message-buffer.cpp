/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        message-buffer.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of MessageBuffer.
 */

#include <message-buffer.h>

#include <dpl/log/log.h>

namespace CKM {

void MessageBuffer::Push(const RawBuffer &data) {
    m_buffer.AppendCopy(&data[0], data.size());
}

RawBuffer MessageBuffer::Pop() {
    size_t size = m_buffer.Size();
    RawBuffer buffer;
    buffer.resize(size + sizeof(size_t));
    memcpy(&buffer[0], &size, sizeof(size_t));
    m_buffer.FlattenConsume(&buffer[sizeof(size_t)], size);
    return buffer;
}

bool MessageBuffer::Ready() {
    CountBytesLeft();
    if (m_bytesLeft == 0)
        return false;
    if (m_bytesLeft > m_buffer.Size())
        return false;
    return true;
}

void MessageBuffer::Read(size_t num, void *bytes) {
    CountBytesLeft();
    if (num > m_bytesLeft) {
        LogDebug("Protocol broken. OutOfData. Asked for: " << num << " Ready: " << m_bytesLeft << " Buffer.size(): " << m_buffer.Size());
        Throw(Exception::OutOfData);
    }

    m_buffer.FlattenConsume(bytes, num);
    m_bytesLeft -= num;
}

void MessageBuffer::Write(size_t num, const void *bytes) {
    m_buffer.AppendCopy(bytes, num);
}

} // namespace CKM

