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
 * @file        client-manager.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Client Manager implementation.
 */
#include <ckm/ckm-manager.h>

#include <safe-buffer.h>
#include <buffer-conversion.h>
#include <client-manager-impl.h>

namespace CKM {

Manager::Manager()
  : m_impl(new ManagerImpl)
{}

Manager::~Manager(){}

int Manager::saveKey(const Alias &alias, const Key &key, const Policy &policy) {
    return m_impl->saveKey(alias, key, policy);
}

int Manager::removeKey(const Alias &alias) {
    return m_impl->removeKey(alias);
}

int Manager::getKey(const Alias &alias, const std::string &password, Key &key) {
    return m_impl->getKey(alias, password, key);
}

int Manager::saveCertificate(const Alias &alias, const Certificate &cert, const Policy &policy) {
    if (cert.empty() || alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;
    return m_impl->saveCertificate(alias, cert, policy);
}

int Manager::removeCertificate(const Alias &alias) {
    if (alias.empty())
        return CKM_API_ERROR_INPUT_PARAM;
    return m_impl->removeCertificate(alias);
}

int Manager::getCertificate(const Alias &alias, const std::string &password, Certificate &cert) {
    return m_impl->getCertificate(alias, password, cert);
}

int Manager::saveData(const Alias &alias, const RawBuffer &data, const Policy &policy) {
    return m_impl->saveData(alias, toSafeBuffer(data), policy);
}

int Manager::removeData(const Alias &alias) {
    return m_impl->removeData(alias);
}

int Manager::getData(const Alias &alias, const std::string &password, RawBuffer &data) {
    SafeBuffer safeBuffer;
    int status = m_impl->getData(alias, password, safeBuffer);
    data = toRawBuffer(safeBuffer);
    return status;
}

int Manager::getKeyAliasVector(AliasVector &av) {
    return m_impl->getKeyAliasVector(av);
}

int Manager::getCertificateAliasVector(AliasVector &av) {
    return m_impl->getCertificateAliasVector(av);
}

int Manager::getDataAliasVector(AliasVector &av) {
    return m_impl->getDataAliasVector(av);
}

int Manager::createKeyPairRSA(
    const int size,              // size in bits [1024, 2048, 4096]
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return m_impl->createKeyPairRSA(size, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int Manager::createKeyPairECDSA(
    ElipticCurve type,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey) 
{
    return m_impl->createKeyPairECDSA(type, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int Manager::getCertificateChain(
    const Certificate &certificate,
    const CertificateVector &untrustedCertificates,
    CertificateVector &certificateChainVector)
{
    return m_impl->getCertificateChain(certificate, untrustedCertificates, certificateChainVector);
}

int Manager::getCertificateChain(
    const Certificate &certificate,
    const AliasVector &untrustedCertificates,
    CertificateVector &certificateChainVector)
{
    return m_impl->getCertificateChain(certificate, untrustedCertificates, certificateChainVector);
}

int Manager::createSignature(
    const Alias &privateKeyAlias,
    const std::string &password,           // password for private_key
    const RawBuffer &message,
    const HashAlgorithm hash,
    const RSAPaddingAlgorithm padding,
    RawBuffer &signature)
{
    SafeBuffer safeBuffer;
    int status = m_impl->createSignature(privateKeyAlias, password, toSafeBuffer(message), hash, padding, safeBuffer);
    signature = toRawBuffer(safeBuffer);
    return status;
}

int Manager::verifySignature(
    const Alias &publicKeyOrCertAlias,
    const std::string &password,           // password for public_key (optional)
    const RawBuffer &message,
    const RawBuffer &signature,
    const HashAlgorithm hash,
    const RSAPaddingAlgorithm padding)
{
    return m_impl->verifySignature(publicKeyOrCertAlias, password, toSafeBuffer(message), toSafeBuffer(signature), hash, padding);
}

int Manager::ocspCheck(const CertificateVector &certificateChainVector, int &ocspStatus)
{
    return m_impl->ocspCheck(certificateChainVector, ocspStatus);
}

} // namespace CKM

