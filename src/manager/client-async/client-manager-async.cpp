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
 * @file       client-manager-async.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <ckm/ckm-manager-async.h>
#include <client-manager-async-impl.h>

namespace CKM {

ManagerAsync::ManagerAsync()
{
    m_impl.reset(new Impl());
}

ManagerAsync::~ManagerAsync()
{
    m_impl.reset();
}

void ManagerAsync::saveKey(const ObserverPtr& observer,
                           const Alias& alias,
                           const KeyShPtr& key,
                           const Policy& policy)
{
    m_impl->saveKey(observer, alias, key, policy);
}

void ManagerAsync::saveCertificate(const ObserverPtr& observer,
                                   const Alias& alias,
                                   const CertificateShPtr& cert,
                                   const Policy& policy)
{
    m_impl->saveCertificate(observer, alias, cert, policy);
}

void ManagerAsync::saveData(const ObserverPtr& observer,
                            const Alias& alias,
                            const RawBuffer& data,
                            const Policy& policy)
{
    m_impl->saveData(observer, alias, data, policy);
}

void ManagerAsync::removeKey(const ObserverPtr& observer, const Alias& alias)
{
    m_impl->removeKey(observer, alias);
}

void ManagerAsync::removeCertificate(const ObserverPtr& observer, const Alias& alias)
{
    m_impl->removeCertificate(observer, alias);
}

void ManagerAsync::removeData(const ObserverPtr& observer, const Alias& alias)
{
    m_impl->removeData(observer, alias);
}

void ManagerAsync::getKey(const ObserverPtr& observer, const Alias& alias, const Password& password)
{
    m_impl->getKey(observer, alias, password);
}

void ManagerAsync::getCertificate(const ObserverPtr& observer,
                                  const Alias& alias,
                                  const Password& password)
{
    m_impl->getCertificate(observer, alias, password);
}

void ManagerAsync::getData(const ObserverPtr& observer,
                           const Alias& alias,
                           const Password& password)
{
    m_impl->getData(observer, alias, password);
}

void ManagerAsync::getKeyAliasVector(const ObserverPtr& observer)
{
    m_impl->getKeyAliasVector(observer);
}

void ManagerAsync::getCertificateAliasVector(const ObserverPtr& observer)
{
    m_impl->getCertificateAliasVector(observer);
}

void ManagerAsync::getDataAliasVector(const ObserverPtr& observer)
{
    m_impl->getDataAliasVector(observer);
}

void ManagerAsync::createKeyPairRSA(const ObserverPtr& observer,
                                    int size,
                                    const Alias& privateKeyAlias,
                                    const Alias& publicKeyAlias,
                                    const Policy& policyPrivateKey,
                                    const Policy& policyPublicKey)
{
    m_impl->createKeyPairRSA(observer,
                             size,
                             privateKeyAlias,
                             publicKeyAlias,
                             policyPrivateKey,
                             policyPublicKey);
}

void ManagerAsync::createKeyPairDSA(const ObserverPtr& observer,
                                    int size,
                                    const Alias& privateKeyAlias,
                                    const Alias& publicKeyAlias,
                                    const Policy& policyPrivateKey,
                                    const Policy& policyPublicKey)
{
    m_impl->createKeyPairDSA(observer,
                             size,
                             privateKeyAlias,
                             publicKeyAlias,
                             policyPrivateKey,
                             policyPublicKey);
}

void ManagerAsync::createKeyPairECDSA(const ObserverPtr& observer,
                                      const ElipticCurve type,
                                      const Alias& privateKeyAlias,
                                      const Alias& publicKeyAlias,
                                      const Policy& policyPrivateKey,
                                      const Policy& policyPublicKey)
{
    m_impl->createKeyPairECDSA(observer,
                               type,
                               privateKeyAlias,
                               publicKeyAlias,
                               policyPrivateKey,
                               policyPublicKey);
}

void ManagerAsync::getCertificateChain(const ObserverPtr& observer,
                                       const CertificateShPtr& certificate,
                                       const CertificateShPtrVector& untrustedCertificates)
{
    m_impl->getCertificateChain(observer, certificate, untrustedCertificates);
}

void ManagerAsync::getCertificateChain(const ObserverPtr& observer,
                                       const CertificateShPtr& certificate,
                                       const AliasVector& untrustedCertificates)
{
    m_impl->getCertificateChain(observer, certificate, untrustedCertificates);
}

void ManagerAsync::createSignature(const ObserverPtr& observer,
                                   const Alias& privateKeyAlias,
                                   const Password& password,
                                   const RawBuffer& message,
                                   const HashAlgorithm hash,
                                   const RSAPaddingAlgorithm padding)
{
    m_impl->createSignature(observer, privateKeyAlias, password, message, hash, padding);
}

void ManagerAsync::verifySignature(const ObserverPtr& observer,
                                   const Alias& publicKeyOrCertAlias,
                                   const Password& password,
                                   const RawBuffer& message,
                                   const RawBuffer& signature,
                                   const HashAlgorithm hash,
                                   const RSAPaddingAlgorithm padding)
{
    m_impl->verifySignature(observer, publicKeyOrCertAlias, password, message, signature, hash, padding);
}

void ManagerAsync::ocspCheck(const ObserverPtr& observer,
                             const CertificateShPtrVector& certificateChainVector)
{
    m_impl->ocspCheck(observer, certificateChainVector);
}

void ManagerAsync::allowAccess(const ObserverPtr& observer,
                               const std::string& alias,
                               const std::string& accessor,
                               AccessRight granted)
{
    m_impl->allowAccess(observer, alias, accessor, granted);
}

void ManagerAsync::denyAccess(const ObserverPtr& observer,
                              const std::string& alias,
                              const std::string& accessor)
{
    m_impl->denyAccess(observer, alias, accessor);
}

} // namespace CKM

