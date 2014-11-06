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
 * @file       client-manager-async-impl.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <stdexcept>

#include <ckm/ckm-error.h>
#include <message-buffer.h>
#include <client-common.h>

#include <client-manager-async-impl.h>

namespace CKM {

int ManagerAsync::Impl::m_counter = 0;

ManagerAsync::Impl::Impl()
{
}

ManagerAsync::Impl::~Impl()
{
}

void ManagerAsync::Impl::saveKey(const ObserverPtr& observer,
                           const Alias& alias,
                           const KeyShPtr& key,
                           const Policy& policy)
{
    observerCheck(observer);
    if (alias.empty() || !key) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    saveBinaryData(observer, alias, toDBDataType(key->getType()), key->getDER(), policy);
}

void ManagerAsync::Impl::saveCertificate(const ObserverPtr& observer,
                                   const Alias& alias,
                                   const CertificateShPtr& cert,
                                   const Policy& policy)
{
    observerCheck(observer);
    if (alias.empty() || !cert) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    saveBinaryData(observer, alias, DBDataType::CERTIFICATE, cert->getDER(), policy);
}

void ManagerAsync::Impl::saveData(const ObserverPtr& observer,
                            const Alias& alias,
                            const RawBuffer& data,
                            const Policy& policy)
{
    observerCheck(observer);
    if (alias.empty() || data.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    saveBinaryData(observer, alias, DBDataType::BINARY_DATA, data, policy);
}

void ManagerAsync::Impl::saveBinaryData(const ManagerAsync::ObserverPtr& observer,
                                        const Alias& alias,
                                        DBDataType dataType,
                                        const RawBuffer& rawData,
                                        const Policy& policy)
{
    try_catch_async([&] {
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::SAVE),
                      m_counter,
                      static_cast<int>(dataType),
                      alias,
                      rawData,
                      PolicySerializable(policy));
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::removeBinaryData(const ManagerAsync::ObserverPtr& observer,
                                          const Alias& alias,
                                          DBDataType dataType)
{
    observerCheck(observer);
    if (alias.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        AliasSupport helper(alias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::REMOVE),
                      m_counter,
                      static_cast<int>(dataType),
                      helper.getName(),
                      helper.getLabel());
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::getBinaryData(const ManagerAsync::ObserverPtr& observer,
                                       const Alias &alias,
                                       DBDataType sendDataType,
                                       const Password &password)
{
    observerCheck(observer);
    if (alias.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        AliasSupport helper(alias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::GET),
                      m_counter,
                      static_cast<int>(sendDataType),
                      helper.getName(),
                      helper.getLabel(),
                      password);
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::createSignature(const ObserverPtr& observer,
                                         const Alias& privateKeyAlias,
                                         const Password& password,
                                         const RawBuffer& message,
                                         const HashAlgorithm hash,
                                         const RSAPaddingAlgorithm padding)
{
    observerCheck(observer);
    if (privateKeyAlias.empty() || message.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        AliasSupport helper(privateKeyAlias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::CREATE_SIGNATURE),
                      m_counter,
                      helper.getName(),
                      helper.getLabel(),
                      password,
                      message,
                      static_cast<int>(hash),
                      static_cast<int>(padding));
    }, [&observer](int error) {observer->ReceivedError(error);});
}

void ManagerAsync::Impl::verifySignature(const ObserverPtr& observer,
                                         const Alias& publicKeyOrCertAlias,
                                         const Password& password,
                                         const RawBuffer& message,
                                         const RawBuffer& signature,
                                         const HashAlgorithm hash,
                                         const RSAPaddingAlgorithm padding)
{
    observerCheck(observer);
    if (publicKeyOrCertAlias.empty() || message.empty() || signature.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        AliasSupport helper(publicKeyOrCertAlias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::VERIFY_SIGNATURE),
                      m_counter,
                      helper.getName(),
                      helper.getLabel(),
                      password,
                      message,
                      signature,
                      static_cast<int>(hash),
                      static_cast<int>(padding));
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::ocspCheck(const ObserverPtr& observer,
                                   const CertificateShPtrVector& certificateChainVector)
{
    observerCheck(observer);
    if (certificateChainVector.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        RawBufferVector rawCertChain;
        for (auto &e: certificateChainVector) {
            rawCertChain.push_back(e->getDER());
        }

        m_counter++;
        auto send = MessageBuffer::Serialize(m_counter, rawCertChain);

        thread()->sendMessage(AsyncRequest(observer,
                                           SERVICE_SOCKET_OCSP,
                                           send.Pop(),
                                           m_counter));
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::setPermission(const ObserverPtr& observer,
                                         const Alias& alias,
                                         const Label& accessor,
                                         Permission newPermission)
{
    observerCheck(observer);
    if (alias.empty() || accessor.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::SET_PERMISSION),
                      m_counter,
                      alias,
                      accessor,
                      static_cast<int>(newPermission));
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::getBinaryDataAliasVector(const ManagerAsync::ObserverPtr& observer,
                                                  DBDataType dataType)
{
    observerCheck(observer);
    try_catch_async([&] {
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::GET_LIST),
                      m_counter,
                      static_cast<int>(dataType));
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::createKeyPair(const ManagerAsync::ObserverPtr& observer,
                                       const KeyType key_type,
                                       const int     additional_param,
                                       const Alias  &privateKeyAlias,
                                       const Alias  &publicKeyAlias,
                                       const Policy &policyPrivateKey,
                                       const Policy &policyPublicKey)
{
    observerCheck(observer);
    if (privateKeyAlias.empty() || publicKeyAlias.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    // input type check
    LogicCommand cmd_type;
    switch(key_type)
    {
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_RSA_PRIVATE:
            cmd_type = LogicCommand::CREATE_KEY_PAIR_RSA;
            break;

        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_DSA_PRIVATE:
            cmd_type = LogicCommand::CREATE_KEY_PAIR_DSA;
            break;

        case KeyType::KEY_ECDSA_PUBLIC:
        case KeyType::KEY_ECDSA_PRIVATE:
            cmd_type = LogicCommand::CREATE_KEY_PAIR_ECDSA;
            break;

        default:
            observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
            return;
    }

    try_catch_async([&] {
        sendToStorage(observer,
                      static_cast<int>(cmd_type),
                      m_counter,
                      static_cast<int>(additional_param),
                      PolicySerializable(policyPrivateKey),
                      PolicySerializable(policyPublicKey),
                      privateKeyAlias,
                      publicKeyAlias);
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::observerCheck(const ManagerAsync::ObserverPtr& observer)
{
    if(!observer)
        throw std::invalid_argument("Empty observer");
}

} // namespace CKM
