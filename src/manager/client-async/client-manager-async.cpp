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

namespace {
RawBufferVector toRawBufferVector(const CertificateShPtrVector& certificates)
{
    RawBufferVector rawBufferVector;
    for (auto &e: certificates) {
        rawBufferVector.push_back(e->getDER());
    }
    return rawBufferVector;
}

LabelNameVector toLabelNameVector(const AliasVector& aliases)
{
    LabelNameVector labelNames;
    for (auto &e: aliases) {
        AliasSupport helper(e);
        labelNames.push_back(std::make_pair(helper.getLabel(), helper.getName()));
    }
    return labelNames;
}

} // namespace anonymous

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

void ManagerAsync::savePKCS12(const ObserverPtr& observer,
                              const Alias &alias,
                              const PKCS12ShPtr &pkcs,
                              const Policy &keyPolicy,
                              const Policy &certPolicy)
{
    m_impl->savePKCS12(observer, alias, pkcs, keyPolicy, certPolicy);
}

void ManagerAsync::removeAlias(const ObserverPtr& observer, const Alias& alias)
{
    m_impl->removeAlias(observer, alias);
}

void ManagerAsync::getKey(const ObserverPtr& observer, const Alias& alias, const Password& password)
{
    m_impl->getBinaryData(observer, alias, DataType::DB_KEY_FIRST, password);
}

void ManagerAsync::getCertificate(const ObserverPtr& observer,
                                  const Alias& alias,
                                  const Password& password)
{
    m_impl->getBinaryData(observer, alias, DataType::CERTIFICATE, password);
}

void ManagerAsync::getData(const ObserverPtr& observer,
                           const Alias& alias,
                           const Password& password)
{
    m_impl->getBinaryData(observer, alias, DataType::BINARY_DATA, password);
}

void ManagerAsync::getPKCS12(const ObserverPtr& observer,
                             const Alias &alias,
                             const Password &keyPassword,
                             const Password &certPassword)
{
    m_impl->getPKCS12(observer, alias, keyPassword, certPassword);
}

void ManagerAsync::getKeyAliasVector(const ObserverPtr& observer)
{
    m_impl->getBinaryDataAliasVector(observer, DataType::DB_KEY_FIRST);
}

void ManagerAsync::getCertificateAliasVector(const ObserverPtr& observer)
{
    m_impl->getBinaryDataAliasVector(observer, DataType::CERTIFICATE);
}

void ManagerAsync::getDataAliasVector(const ObserverPtr& observer)
{
    m_impl->getBinaryDataAliasVector(observer, DataType::BINARY_DATA);
}

void ManagerAsync::createKeyPairRSA(const ObserverPtr& observer,
                                    int size,
                                    const Alias& privateKeyAlias,
                                    const Alias& publicKeyAlias,
                                    const Policy& policyPrivateKey,
                                    const Policy& policyPublicKey)
{
    m_impl->createKeyPair(observer,
                          KeyType::KEY_RSA_PUBLIC,
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
    m_impl->createKeyPair(observer,
                          KeyType::KEY_DSA_PUBLIC,
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
    m_impl->createKeyPair(observer,
                          KeyType::KEY_ECDSA_PUBLIC,
                          static_cast<int>(type),
                          privateKeyAlias,
                          publicKeyAlias,
                          policyPrivateKey,
                          policyPublicKey);
}

void ManagerAsync::createKeyAES(const ObserverPtr& /*observer*/,
                                int /*size*/,
                                const Alias &/*keyAlias*/,
                                const Policy &/*policyKey*/)
{
}

void ManagerAsync::getCertificateChain(const ObserverPtr& observer,
                                       const CertificateShPtr& certificate,
                                       const CertificateShPtrVector& untrustedCertificates,
                                       const CertificateShPtrVector& trustedCertificates,
                                       bool useSystemTrustedCertificates)
{
    m_impl->getCertChain(observer,
                         LogicCommand::GET_CHAIN_CERT,
                         certificate,
                         toRawBufferVector(untrustedCertificates),
                         toRawBufferVector(trustedCertificates),
                         useSystemTrustedCertificates);
}

void ManagerAsync::getCertificateChain(const ObserverPtr& observer,
                                       const CertificateShPtr& certificate,
                                       const AliasVector& untrustedCertificates,
                                       const AliasVector& trustedCertificates,
                                       bool useSystemTrustedCertificates)
{
    m_impl->getCertChain(observer,
                         LogicCommand::GET_CHAIN_ALIAS,
                         certificate,
                         toLabelNameVector(untrustedCertificates),
                         toLabelNameVector(trustedCertificates),
                         useSystemTrustedCertificates);
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

void ManagerAsync::setPermission(const ObserverPtr& observer,
                                 const Alias& alias,
                                 const Label& accessor,
                                 PermissionMask permissionMask)
{
    m_impl->setPermission(observer, alias, accessor, permissionMask);
}

} // namespace CKM

