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
 * @file        client-manager-impl.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Manager implementation.
 */
#pragma once

#include <protocols.h>

#include <ckm/ckm-type.h>
#include <ckm/key-manager.h>

namespace CKM {

class Manager::ManagerImpl {
public:
    ManagerImpl()
      : m_counter(0)
    {}
    virtual ~ManagerImpl(){}

    int saveKey(const Alias &alias, const Key &key, const Policy &policy);
    int removeKey(const Alias &alias);
    int getKey(const Alias &alias, const RawData &password, Key &key);

    int saveCertificate(const Alias &alias, const Certificate &cert, const Policy &policy);
    int removeCertificate(const Alias &alias);
    int getCertificate(const Alias &alias, const RawData &password, Certificate &cert);

protected:
    int saveBinaryData(
        const Alias &alias,
        DBDataType dataType,
        const RawData &rawData,
        const Policy &policy);

    int removeBinaryData(
        const Alias &alias,
        DBDataType dataType);
        
    int getBinaryData(
        const Alias &alias,
        DBDataType sendDataType,
        const RawData &password,
        DBDataType &recvDataType,
        RawData &rawData);

    int m_counter;
};

} // namespace CKM

