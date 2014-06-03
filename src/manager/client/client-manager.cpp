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
 * @file        client-manager.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Client Manager implementation.
 */
#include <ckm/key-manager.h>

#include <client-manager-impl.h>

namespace CKM {

Manager::Manager()
  : m_impl(new ManagerImpl)
{}

Manager::~Manager(){}

int Manager::saveKey(const Alias &alias, const Key &key, const Policy &policy) {
    return m_impl->saveKey(alias, key, policy);
}

int Manager::removeKey(const Alias &alias) {
    return m_impl->removeKey(alias);
}

int Manager::getKey(const Alias &alias, const RawData &password, Key &key) {
    return m_impl->getKey(alias, password, key);
}

int Manager::saveCertificate(const Alias &alias, const Certificate &cert, const Policy &policy) {
    return m_impl->saveCertificate(alias, cert, policy);
}

int Manager::removeCertificate(const Alias &alias) {
    return m_impl->removeCertificate(alias);
}

int Manager::getCertificate(const Alias &alias, const RawData &password, Certificate &cert) {
    return m_impl->getCertificate(alias, password, cert);
}

int Manager::saveData(const Alias &alias, const RawData &data, const Policy &policy) {
    return m_impl->saveData(alias, data, policy);
}

int Manager::removeData(const Alias &alias) {
    return m_impl->removeData(alias);
}

int Manager::getData(const Alias &alias, const RawData &password, RawData &data) {
    return m_impl->getData(alias, password, data);
}

} // namespace CKM

