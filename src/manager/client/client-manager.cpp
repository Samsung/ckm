/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckm-manager.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Manager implementation for client library.
 */
#include <dpl/log/log.h>

#include <ckm/ckm-manager.h>
#include <client-manager-impl.h>

namespace CKM {

Manager::Manager()
  : m_impl(new Impl())
{}

Manager::~Manager(){}

int Manager::saveKey(const Alias &alias, const KeyShPtr &key, const Policy &policy) {
    return m_impl->saveKey(alias, key, policy);
}

int Manager::saveCertificate(const Alias &alias, const CertificateShPtr &cert, const Policy &policy) {
    return m_impl->saveCertificate(alias, cert, policy);
}

int Manager::savePKCS12(
    const Alias &alias,
    const PKCS12ShPtr &pkcs,
    const Policy &keyPolicy,
    const Policy &certPolicy)
{
    return m_impl->savePKCS12(alias, pkcs, keyPolicy, certPolicy);
}

int Manager::saveData(const Alias &alias, const RawBuffer &data, const Policy &policy) {
    return m_impl->saveData(alias, data, policy);
}

int Manager::removeAlias(const Alias &alias) {
    return m_impl->removeAlias(alias);
}

int Manager::getKey(const Alias &alias, const Password &password, KeyShPtr &key) {
    return m_impl->getKey(alias, password, key);
}

int Manager::getCertificate(
    const Alias &alias,
    const Password &password,
    CertificateShPtr &certificate)
{
    return m_impl->getCertificate(alias, password, certificate);
}

int Manager::getData(const Alias &alias, const Password &password, RawBuffer &data) {
    return m_impl->getData(alias, password, data);
}

int Manager::getPKCS12(const Alias &alias, PKCS12ShPtr &pkcs) {
    return m_impl->getPKCS12(alias, pkcs);
}

int Manager::getPKCS12(
    const Alias &alias,
    const Password &keyPass,
    const Password &certPass,
    PKCS12ShPtr &pkcs)
{
    return m_impl->getPKCS12(alias, keyPass, certPass, pkcs);
}

int Manager::getKeyAliasVector(AliasVector &aliasVector) {
    return m_impl->getKeyAliasVector(aliasVector);
}

int Manager::getCertificateAliasVector(AliasVector &aliasVector) {
    return m_impl->getCertificateAliasVector(aliasVector);
}

int Manager::getDataAliasVector(AliasVector &aliasVector) {
    return m_impl->getDataAliasVector(aliasVector);
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

int Manager::createKeyPairDSA(
    const int size,              // size in bits [1024, 2048, 3072, 4096]
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return m_impl->createKeyPairDSA(size, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int Manager::createKeyPairECDSA(
    const ElipticCurve type,
    const Alias &privateKeyAlias,
    const Alias &publicKeyAlias,
    const Policy &policyPrivateKey,
    const Policy &policyPublicKey)
{
    return m_impl->createKeyPairECDSA(type, privateKeyAlias, publicKeyAlias, policyPrivateKey, policyPublicKey);
}

int Manager::createKeyAES(
    const int size,
    const Alias &keyAlias,
    const Policy &policyKey)
{
    return m_impl->createKeyAES(size, keyAlias, policyKey);
}

int Manager::getCertificateChain(
    const CertificateShPtr &certificate,
    const CertificateShPtrVector &untrustedCertificates,
    const CertificateShPtrVector &trustedCertificates,
    bool useTrustedSystemCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    return m_impl->getCertificateChain(
        certificate,
        untrustedCertificates,
        trustedCertificates,
        useTrustedSystemCertificates,
        certificateChainVector);
}

int Manager::getCertificateChain(
    const CertificateShPtr &certificate,
    const AliasVector &untrustedCertificates,
    const AliasVector &trustedCertificates,
    bool useTrustedSystemCertificates,
    CertificateShPtrVector &certificateChainVector)
{
    return m_impl->getCertificateChain(
        certificate,
        untrustedCertificates,
        trustedCertificates,
        useTrustedSystemCertificates,
        certificateChainVector);
}

int Manager::createSignature(
    const Alias &privateKeyAlias,
    const Password &password,
    const RawBuffer &message,
    const HashAlgorithm hash,
    const RSAPaddingAlgorithm padding,
    RawBuffer &signature)
{
    return m_impl->createSignature(
        privateKeyAlias,
        password,
        message,
        hash,
        padding,
        signature);
}

int Manager::verifySignature(
    const Alias &publicKeyOrCertAlias,
    const Password &password,           // password for public_key (optional)
    const RawBuffer &message,
    const RawBuffer &signature,
    const HashAlgorithm hash,
    const RSAPaddingAlgorithm padding)
{
    return m_impl->verifySignature(
        publicKeyOrCertAlias,
        password,
        message,
        signature,
        hash,
        padding);
}

int Manager::ocspCheck(const CertificateShPtrVector &certificateChainVector, int &ocspStatus) {
    return m_impl->ocspCheck(certificateChainVector, ocspStatus);
}

int Manager::setPermission(
    const Alias &alias,
    const Label &accessor,
    PermissionMask permissionMask)
{
    return m_impl->setPermission(alias, accessor, permissionMask);
}

int Manager::encrypt(
    const CryptoAlgorithm &algo,
    const Alias &keyAlias,
    const Password &password,
    const RawBuffer& plain,
    RawBuffer& encrypted)
{
    return m_impl->encrypt(algo, keyAlias, password, plain, encrypted);
}

int Manager::decrypt(
    const CryptoAlgorithm &algo,
    const Alias &keyAlias,
    const Password &password,
    const RawBuffer& encrypted,
    RawBuffer& decrypted)
{
    return m_impl->decrypt(algo, keyAlias, password, encrypted, decrypted);
}

ManagerShPtr Manager::create() {
    try {
        return std::make_shared<Manager>();
    } catch (const std::bad_alloc &) {
        LogDebug("Bad alloc was caught during Manager::Impl creation.");
    } catch (...) {
        LogError("Critical error: Unknown exception was caught during Manager::Impl creation!");
    }
    return ManagerShPtr();
}

} // namespace CKM

