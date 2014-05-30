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
    m_impl->saveKey(alias, key, policy);
}

int Manager::removeKey(const Alias &alias) {
    m_impl->removeKey(alias);
}

int Manager::getKey(const Alias &alias, Key &key, const RawData &password) {
    m_impl->getKey(alias, password, key);
}

} // namespace CKM

