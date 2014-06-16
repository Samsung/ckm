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
 * @file        client-certificate.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Certificate class implementation.
 */

#include <ckm/key-manager.h>

#include <certificate-impl.h>

namespace CKM {

Certificate::Certificate(){}

Certificate::Certificate(const RawBuffer &rawData, DataFormat format)
  : m_impl(new CertificateImpl(rawData, format))
{}

Certificate::Certificate(const Certificate &second) {
    m_impl = second.m_impl;
}

Certificate& Certificate::operator=(const Certificate &second) {
    m_impl = second.m_impl;
    return *this;
}

bool Certificate::empty() const {
    if (m_impl)
        return m_impl->empty();
    return true;
}

RawBuffer Certificate::getDER() const {
    if (m_impl)
        return m_impl->getDER();
    return RawBuffer();
}

void* Certificate::getX509() {
    // TODO
    return NULL;
}

} // namespace CKM

