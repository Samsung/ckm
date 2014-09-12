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
    int getKey(const Alias &alias, const std::string &password, Key &key);
    int requestKeyAliasVector(AliasVector &aliasVector);

    int saveCertificate(const Alias &alias, const Certificate &cert, const Policy &policy);
    int removeCertificate(const Alias &alias);
    int getCertificate(const Alias &alias, const std::string &password, Certificate &cert);
    int requestCertificateAliasVector(AliasVector &aliasVector);

    int saveData(const Alias &alias, const RawBuffer &rawData, const Policy &policy);
    int removeData(const Alias &alias);
    int getData(const Alias &alias, const std::string &password, RawBuffer &cert);
    int requestDataAliasVector(AliasVector &aliasVector);
    
    int createKeyPairRSA(
        const int size,              // size in bits [1024, 2048, 4096]
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy());

    int createKeyPairECDSA(
        ElipticCurve type,
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy());

protected:
    int saveBinaryData(
        const Alias &alias,
        DBDataType dataType,
        const RawBuffer &rawData,
        const Policy &policy);

    int removeBinaryData(
        const Alias &alias,
        DBDataType dataType);
        
    int getBinaryData(
        const Alias &alias,
        DBDataType sendDataType,
        const std::string &password,
        DBDataType &recvDataType,
        RawBuffer &rawData);

    int requestBinaryDataAliasVector(
        DBDataType sendDataType,
        AliasVector &aliasVector);

    int m_counter;
};

} // namespace CKM

