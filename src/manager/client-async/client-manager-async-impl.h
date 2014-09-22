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
 */
/*
 * @file       client-manager-async-impl.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <ckm/ckm-manager-async.h>
#include <memory>
#include <connection-thread.h>
#include <protocols.h>
#include <noncopyable.h>

namespace CKM {

class ManagerAsync::Impl
{
public:
    Impl();

    NONCOPYABLE(Impl);

    virtual ~Impl();

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

    void removeKey(const ObserverPtr& observer, const Alias& alias);
    void removeCertificate(const ObserverPtr& observer, const Alias& alias);
    void removeData(const ObserverPtr& observer, const Alias& alias);

    void getKey(const ObserverPtr& observer, const Alias& alias, const Password& password);
    void getCertificate(const ObserverPtr& observer, const Alias& alias, const Password& password);
    void getData(const ObserverPtr& observer, const Alias& alias, const Password& password);

    void getKeyAliasVector(const ObserverPtr& observer);
    void getCertificateAliasVector(const ObserverPtr& observer);
    void getDataAliasVector(const ObserverPtr& observer);

    void createKeyPairRSA(
            const ObserverPtr& observer,
            int size,
            const Alias& privateKeyAlias,
            const Alias& publicKeyAlias,
            const Policy& policyPrivateKey,
            const Policy& policyPublicKey);
    void createKeyPairDSA(
            const ObserverPtr& observer,
            int size,
            const Alias& privateKeyAlias,
            const Alias& publicKeyAlias,
            const Policy& policyPrivateKey,
            const Policy& policyPublicKey);
    void createKeyPairECDSA(
            const ObserverPtr& observer,
            const ElipticCurve type,
            const Alias& privateKeyAlias,
            const Alias& publicKeyAlias,
            const Policy& policyPrivateKey,
            const Policy& policyPublicKey);

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
            const Password& password,
            const RawBuffer& message,
            const HashAlgorithm hash,
            const RSAPaddingAlgorithm padding);
    void verifySignature(
            const ObserverPtr& observer,
            const Alias& publicKeyOrCertAlias,
            const Password& password,
            const RawBuffer& message,
            const RawBuffer& signature,
            const HashAlgorithm hash,
            const RSAPaddingAlgorithm padding);

    void ocspCheck(
            const ObserverPtr& observer,
            const CertificateShPtrVector& certificateChainVector);

    void allowAccess(
            const ObserverPtr& observer,
            const std::string& alias,
            const std::string& accessor,
            AccessRight granted);
    void denyAccess(
            const ObserverPtr& observer,
            const std::string& alias,
            const std::string& accessor);

private:
    void saveBinaryData(const ManagerAsync::ObserverPtr& observer,
                        const Alias& alias,
                        DBDataType dataType,
                        const RawBuffer& rawData,
                        const Policy& policy);

    void observerCheck(const ManagerAsync::ObserverPtr& observer);

    typedef std::unique_ptr<ConnectionThread> ConnectionThreadPtr;

    ConnectionThreadPtr& thread() {
        if (!m_thread || m_thread->finished()) {
            m_thread.reset(new ConnectionThread());
            m_thread->run();
        }
        return m_thread;
    }

    ConnectionThreadPtr m_thread;

    static int m_counter;
};

} // namespace CKM
