/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
    void savePKCS12(
            const ObserverPtr& observer,
            const Alias &alias,
            const PKCS12ShPtr &pkcs,
            const Policy &keyPolicy,
            const Policy &certPolicy);

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

    void setPermission(
            const ObserverPtr& observer,
            const Alias& alias,
            const Label& accessor,
            PermissionMask permissionMask);

    // generic methods
    void saveBinaryData(
            const ManagerAsync::ObserverPtr& observer,
            const Alias& alias,
            DataType dataType,
            const RawBuffer& rawData,
            const Policy& policy);

    void removeAlias(
            const ManagerAsync::ObserverPtr& observer,
            const Alias &alias);

    void getBinaryData(
            const ManagerAsync::ObserverPtr& observer,
            const Alias &alias,
            DataType sendDataType,
            const Password &password);

    void getPKCS12(
            const ManagerAsync::ObserverPtr& observer,
            const Alias &alias,
            const Password &keyPassword,
            const Password &certPassword);

    void getBinaryDataAliasVector(
            const ManagerAsync::ObserverPtr& observer,
            DataType dataType);

    void createKeyPair(
            const ManagerAsync::ObserverPtr& observer,
            const KeyType key_type,
            const int     additional_param,
            const Alias  &privateKeyAlias,
            const Alias  &publicKeyAlias,
            const Policy &policyPrivateKey,
            const Policy &policyPublicKey);

    void createKeyAES(
            const ManagerAsync::ObserverPtr& observer,
            const size_t  size,
            const Alias  &keyAlias,
            const Policy &policyKey);

    template <typename T>
    void getCertChain(
            const ManagerAsync::ObserverPtr& observer,
            LogicCommand command,
            const CertificateShPtr &certificate,
            const T &untrusted,
            const T &trusted,
            bool useSystemTrustedCertificates)
    {
        observerCheck(observer);
        if (!certificate) {
            observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
            return;
        }
        try_catch_async([&] {
            sendToStorage(observer,
                          static_cast<int>(command),
                          m_counter,
                          certificate->getDER(),
                          untrusted,
                          trusted,
                          useSystemTrustedCertificates);
        }, [&observer](int error){ observer->ReceivedError(error); } );
    }

    void crypt(
            const ObserverPtr& observer,
            const CryptoAlgorithm& algo,
            const Alias& keyAlias,
            const Password& password,
            const RawBuffer& input,
            bool encryption);

private:

    template <typename... Args>
    void sendToStorage(const ManagerAsync::ObserverPtr& observer, const Args&... args)
    {
        m_counter++; // yes, it changes m_counter argument passed in args

        auto send = MessageBuffer::Serialize(args...);
        thread()->sendMessage(AsyncRequest(observer,
                                           SERVICE_SOCKET_CKM_STORAGE,
                                           send.Pop(),
                                           m_counter));
    }

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
