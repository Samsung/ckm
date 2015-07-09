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
    Try {
        saveBinaryData(observer, alias, DataType(key->getType()), key->getDER(), policy);
    } Catch(DataType::Exception::Base) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
    }
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
    saveBinaryData(observer, alias, DataType::CERTIFICATE, cert->getDER(), policy);
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
    saveBinaryData(observer, alias, DataType::BINARY_DATA, data, policy);
}

void ManagerAsync::Impl::saveBinaryData(const ManagerAsync::ObserverPtr& observer,
                                        const Alias& alias,
                                        DataType dataType,
                                        const RawBuffer& rawData,
                                        const Policy& policy)
{
    try_catch_async([&] {
        AliasSupport helper(alias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::SAVE),
                      m_counter,
                      static_cast<int>(dataType),
                      helper.getName(),
                      helper.getLabel(),
                      rawData,
                      PolicySerializable(policy));
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::savePKCS12(const ManagerAsync::ObserverPtr& observer,
                                    const Alias &alias,
                                    const PKCS12ShPtr &pkcs,
                                    const Policy &keyPolicy,
                                    const Policy &certPolicy)
{
    try_catch_async([&] {
        AliasSupport helper(alias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::SAVE_PKCS12),
                      m_counter,
                      helper.getName(),
                      helper.getLabel(),
                      PKCS12Serializable(*pkcs.get()),
                      PolicySerializable(keyPolicy),
                      PolicySerializable(certPolicy));

    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::removeAlias(const ManagerAsync::ObserverPtr& observer,
                                     const Alias& alias)
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
                      helper.getName(),
                      helper.getLabel());
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::getBinaryData(const ManagerAsync::ObserverPtr& observer,
                                       const Alias &alias,
                                       DataType sendDataType,
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

void ManagerAsync::Impl::getPKCS12(const ManagerAsync::ObserverPtr& observer,
                                   const Alias &alias,
                                   const Password &passwordKey,
                                   const Password &passwordCert)
{
    observerCheck(observer);
    if (alias.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        AliasSupport helper(alias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::GET_PKCS12),
                      m_counter,
                      helper.getName(),
                      helper.getLabel(),
                      passwordKey,
                      passwordCert);
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
            if(!e || e->empty())
                return observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
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
                                       PermissionMask permissionMask)
{
    observerCheck(observer);
    if (alias.empty() || accessor.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    try_catch_async([&] {
        AliasSupport helper(alias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::SET_PERMISSION),
                      m_counter,
                      helper.getName(),
                      helper.getLabel(),
                      accessor,
                      permissionMask);
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::getBinaryDataAliasVector(const ManagerAsync::ObserverPtr& observer,
                                                  DataType dataType)
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
    CryptoAlgorithm keyGenAlgorithm;
    switch(key_type)
    {
        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_RSA_PRIVATE:
            keyGenAlgorithm.setParam(ParamName::ALGO_TYPE, AlgoType::RSA_GEN);
            keyGenAlgorithm.setParam(ParamName::GEN_KEY_LEN, additional_param);
            break;

        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_DSA_PRIVATE:
            keyGenAlgorithm.setParam(ParamName::ALGO_TYPE, AlgoType::DSA_GEN);
            keyGenAlgorithm.setParam(ParamName::GEN_KEY_LEN, additional_param);
            break;

        case KeyType::KEY_ECDSA_PUBLIC:
        case KeyType::KEY_ECDSA_PRIVATE:
            keyGenAlgorithm.setParam(ParamName::ALGO_TYPE, AlgoType::ECDSA_GEN);
            keyGenAlgorithm.setParam(ParamName::GEN_EC, additional_param);
            break;

        default:
            observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
            return;
    }

    try_catch_async([&] {
        AliasSupport prvHelper(privateKeyAlias);
        AliasSupport pubHelper(publicKeyAlias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::CREATE_KEY_PAIR),
                      m_counter,
                      CryptoAlgorithmSerializable(keyGenAlgorithm),
                      PolicySerializable(policyPrivateKey),
                      PolicySerializable(policyPublicKey),
                      prvHelper.getName(),
                      prvHelper.getLabel(),
                      pubHelper.getName(),
                      pubHelper.getLabel());
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::createKeyAES(const ManagerAsync::ObserverPtr& observer,
                                      const size_t  size,
                                      const Alias  &keyAlias,
                                      const Policy &policyKey)
{
    observerCheck(observer);
    if (keyAlias.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }

    try_catch_async([&] {
        AliasSupport aliasHelper(keyAlias);
        sendToStorage(observer,
                      static_cast<int>(LogicCommand::CREATE_KEY_AES),
                      m_counter,
                      static_cast<int>(size),
                      PolicySerializable(policyKey),
                      aliasHelper.getName(),
                      aliasHelper.getLabel());
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::observerCheck(const ManagerAsync::ObserverPtr& observer)
{
    if(!observer)
        throw std::invalid_argument("Empty observer");
}

void ManagerAsync::Impl::crypt(
        const ObserverPtr& observer,
        const CryptoAlgorithm& algo,
        const Alias& keyAlias,
        const Password& password,
        const RawBuffer& input,
        bool encryption)
{
    observerCheck(observer);
    if (input.empty() || keyAlias.empty())
        return observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);

    try_catch_async([&] {
        AliasSupport helper(keyAlias);
        CryptoAlgorithmSerializable cas(algo);
        m_counter++;

        auto send = MessageBuffer::Serialize(
                static_cast<int>(encryption?EncryptionCommand::ENCRYPT:EncryptionCommand::DECRYPT),
                m_counter,
                cas,
                helper.getName(),
                helper.getLabel(),
                password,
                input);
        thread()->sendMessage(AsyncRequest(observer,
                                           SERVICE_SOCKET_ENCRYPTION,
                                           send.Pop(),
                                           m_counter));
    }, [&observer](int error){ observer->ReceivedError(error); } );
}

} // namespace CKM
