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

#include <client-manager-async-impl.h>
#include <ckm/ckm-error.h>
#include <message-buffer.h>
#include <client-common.h>
#include <stdexcept>

namespace CKM {

int ManagerAsync::Impl::m_counter = 0;

ManagerAsync::Impl::Impl()
{
}

ManagerAsync::Impl::~Impl()
{
}

void ManagerAsync::Impl::saveKey(const ManagerAsync::ObserverPtr& observer,
                                 const Alias& alias,
                                 const KeyShPtr& key,
                                 const Policy& policy)
{
    observerCheck(observer);

    if (!key) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }
    saveBinaryData(observer, alias, toDBDataType(key->getType()), key->getDER(), policy);
}

void ManagerAsync::Impl::saveCertificate(const ObserverPtr& observer,
                                         const Alias& /*alias*/,
                                         const CertificateShPtr& /*cert*/,
                                         const Policy& /*policy*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::saveData(const ObserverPtr& observer,
                                  const Alias& /*alias*/,
                                  const RawBuffer& /*data*/,
                                  const Policy& /*policy*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::removeKey(const ObserverPtr& observer, const Alias& /*alias*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::removeCertificate(const ObserverPtr& observer, const Alias& /*alias*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::removeData(const ObserverPtr& observer, const Alias& /*alias*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::getKey(const ObserverPtr& observer,
                                const Alias& /*alias*/,
                                const Password& /*password*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::getCertificate(const ObserverPtr& observer,
                                        const Alias& /*alias*/,
                                        const Password& /*password*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::getData(const ObserverPtr& observer,
                                 const Alias& /*alias*/,
                                 const Password& /*password*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::getKeyAliasVector(const ObserverPtr& observer)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::getCertificateAliasVector(const ObserverPtr& observer)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::getDataAliasVector(const ObserverPtr& observer)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::createKeyPairRSA(const ObserverPtr& observer,
                                          int /*size*/,
                                          const Alias& /*privateKeyAlias*/,
                                          const Alias& /*publicKeyAlias*/,
                                          const Policy& /*policyPrivateKey*/,
                                          const Policy& /*policyPublicKey*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::createKeyPairDSA(const ObserverPtr& observer,
                                          int /*size*/,
                                          const Alias& /*privateKeyAlias*/,
                                          const Alias& /*publicKeyAlias*/,
                                          const Policy& /*policyPrivateKey*/,
                                          const Policy& /*policyPublicKey*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}
void ManagerAsync::Impl::createKeyPairECDSA(const ObserverPtr& observer,
                                            const ElipticCurve /*type*/,
                                            const Alias& /*privateKeyAlias*/,
                                            const Alias& /*publicKeyAlias*/,
                                            const Policy& /*policyPrivateKey*/,
                                            const Policy& /*policyPublicKey*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::getCertificateChain(const ObserverPtr& observer,
                                             const CertificateShPtr& /*certificate*/,
                                             const CertificateShPtrVector& /*untrustedCertificates*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::getCertificateChain(const ObserverPtr& observer,
                                             const CertificateShPtr& /*certificate*/,
                                             const AliasVector& /*untrustedCertificates*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::createSignature(const ObserverPtr& observer,
                                         const Alias& /*privateKeyAlias*/,
                                         const Password& /*password*/,
                                         const RawBuffer& /*message*/,
                                         const HashAlgorithm /*hash*/,
                                         const RSAPaddingAlgorithm /*padding*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::verifySignature(const ObserverPtr& observer,
                                         const Alias& /*publicKeyOrCertAlias*/,
                                         const Password& /*password*/,
                                         const RawBuffer& /*message*/,
                                         const RawBuffer& /*signature*/,
                                         const HashAlgorithm /*hash*/,
                                         const RSAPaddingAlgorithm /*padding*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::ocspCheck(const ObserverPtr& observer,
                                   const CertificateShPtrVector& /*certificateChainVector*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::allowAccess(const ObserverPtr& observer,
                                     const std::string& /*alias*/,
                                     const std::string& /*accessor*/,
                                     AccessRight /*granted*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::denyAccess(const ObserverPtr& observer,
                                    const std::string& /*alias*/,
                                    const std::string& /*accessor*/)
{
    observerCheck(observer);
    observer->ReceivedError(CKM_API_ERROR_UNKNOWN);
}

void ManagerAsync::Impl::saveBinaryData(const ManagerAsync::ObserverPtr& observer,
                                        const Alias& alias,
                                        DBDataType dataType,
                                        const RawBuffer& rawData,
                                        const Policy& policy)
{
    if (alias.empty() || rawData.empty()) {
        observer->ReceivedError(CKM_API_ERROR_INPUT_PARAM);
        return;
    }

    try_catch_async([&] {
        m_counter++;

        auto send = MessageBuffer::Serialize(static_cast<int>(LogicCommand::SAVE),
                                             m_counter,
                                             static_cast<int>(dataType),
                                             alias,
                                             rawData,
                                             PolicySerializable(policy));

        thread()->sendMessage(AsyncRequest(observer,
                                           SERVICE_SOCKET_CKM_STORAGE,
                                           send.Pop(),
                                           m_counter));

    }, [&observer](int error){ observer->ReceivedError(error); } );
}

void ManagerAsync::Impl::observerCheck(const ManagerAsync::ObserverPtr& observer)
{
    if(!observer)
        throw std::invalid_argument("Empty observer");
}

} // namespace CKM
