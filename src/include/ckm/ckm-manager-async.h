/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckm-manager-async.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Async key manager API.
 */
#pragma once

#include <memory>

#include <ckm/ckm-certificate.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-key.h>
#include <ckm/ckm-type.h>

// Central Key Manager namespace
namespace CKM {

// Asynchronous interface to Central Key Manager. This implementation uses
// internal thread for connection. Key Manager is not thread safe.
class ManagerAsync
{
public:
    class Impl;

    ManagerAsync();

    ManagerAsync(const ManagerAsync&) = delete;
    ManagerAsync& operator=(const ManagerAsync&) = delete;

    // Observer will observer custom operation.
    struct Observer {
        virtual void ReceivedError(int error) = 0;

        virtual void ReceivedSaveKey() {}
        virtual void ReceivedSaveCertificate() {}
        virtual void ReceivedSaveData() {}

        virtual void ReceivedRemovedAlias() {}

        virtual void ReceivedKey(Key &&) {}
        virtual void ReceivedCertificate(Certificate &&) {}
        virtual void ReceivedData(RawBuffer &&) {}

        virtual void ReceivedKeyAliasVector(AliasVector &&) {}
        virtual void ReceivedCertificateAliasVector(AliasVector &&) {}
        virtual void ReceivedDataAliasVector(AliasVector &&) {}

        virtual void ReceivedCreateKeyPairRSA() {}
        virtual void ReceivedCreateKeyPairDSA() {}
        virtual void ReceivedCreateKeyPairECDSA() {}

        virtual void ReceivedGetCertificateChain(CertificateShPtrVector &&) {}

        virtual void ReceivedCreateSignature(RawBuffer &&) {}
        virtual void ReceivedVerifySignature() {}

        virtual void ReceivedOCSPCheck(int) {}

        virtual void ReceivedSetPermission() {}

        virtual ~Observer() {}
    };

    typedef std::shared_ptr<Observer> ObserverPtr;

    virtual ~ManagerAsync();

    void saveKey(
            const ObserverPtr& observer,
            const Alias& alias,
            const KeyShPtr& key,
            const Policy& policy);
    void saveCertificate(
            const ObserverPtr& observer,
            const Alias& alias,
            const CertificateShPtr& cert,
            const Policy& policy);
    void saveData(
            const ObserverPtr& observer,
            const Alias& alias,
            const RawBuffer& data,
            const Policy& policy);

    void removeAlias(const ObserverPtr& observer, const Alias& alias);

    void getKey(const ObserverPtr& observer, const Alias& alias, const Password& password);
    void getCertificate(const ObserverPtr& observer, const Alias& alias, const Password& password);
    void getData(const ObserverPtr& observer, const Alias& alias, const Password& password);

    // send request for list of all keys/certificates/data that application/user may use
    void getKeyAliasVector(const ObserverPtr& observer);
    void getCertificateAliasVector(const ObserverPtr& observer);
    void getDataAliasVector(const ObserverPtr& observer);

    void createKeyPairRSA(
            const ObserverPtr& observer,
            int size,
            const Alias& privateKeyAlias,
            const Alias& publicKeyAlias,
            const Policy& policyPrivateKey = Policy(),
            const Policy& policyPublicKey = Policy());
    void createKeyPairDSA(
            const ObserverPtr& observer,
            int size,
            const Alias& privateKeyAlias,
            const Alias& publicKeyAlias,
            const Policy& policyPrivateKey = Policy(),
            const Policy& policyPublicKey = Policy());
    void createKeyPairECDSA(
            const ObserverPtr& observer,
            const ElipticCurve type,
            const Alias& privateKeyAlias,
            const Alias& publicKeyAlias,
            const Policy& policyPrivateKey = Policy(),
            const Policy& policyPublicKey = Policy());

    void getCertificateChain(
            const ObserverPtr& observer,
            const CertificateShPtr& certificate,
            const CertificateShPtrVector& untrustedCertificates);
    void getCertificateChain(
            const ObserverPtr& observer,
            const CertificateShPtr& certificate,
            const AliasVector& untrustedCertificates);

    void createSignature(
            const ObserverPtr& observer,
            const Alias& privateKeyAlias,
            const Password& password,           // password for private_key
            const RawBuffer& message,
            const HashAlgorithm hash,
            const RSAPaddingAlgorithm padding);
    void verifySignature(
            const ObserverPtr& observer,
            const Alias& publicKeyOrCertAlias,
            const Password& password,           // password for public_key (optional)
            const RawBuffer& message,
            const RawBuffer& signature,
            const HashAlgorithm hash,
            const RSAPaddingAlgorithm padding);

    // This function will check all certificates in chain except Root CA.
    // This function will delegate task to service. You may use this even
    // if application does not have permission to use network.
    void ocspCheck(
            const ObserverPtr& observer,
            const CertificateShPtrVector& certificateChainVector);

    void setPermission(
            const ObserverPtr& observer,
            const Alias& alias,
            const Label& accessor,
            Permission newPermission);

private:
    std::unique_ptr<Impl> m_impl;
};

} // namespace CKM

