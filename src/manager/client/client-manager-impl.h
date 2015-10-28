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
 * @file        client-manager-impl.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Manager implementation.
 */
#pragma once

#include <data-type.h>
#include <client-common.h>
#include <ckm/ckm-type.h>
#include <ckm/ckm-key.h>
#include <ckm/ckm-manager.h>

namespace CKM {

class Manager::Impl {
public:
    Impl();
    virtual ~Impl(){}

    int saveKey(const Alias &alias, const KeyShPtr &key, const Policy &policy);
    int getKey(const Alias &alias, const Password &password, KeyShPtr &key);
    int getKeyAliasVector(AliasVector &aliasVector);

    int saveCertificate(const Alias &alias, const CertificateShPtr &cert, const Policy &policy);
    int getCertificate(const Alias &alias, const Password &password, CertificateShPtr &cert);
    int getCertificateAliasVector(AliasVector &aliasVector);

    int saveData(const Alias &alias, const RawBuffer &rawData, const Policy &policy);
    int getData(const Alias &alias, const Password &password, RawBuffer &cert);
    int getDataAliasVector(AliasVector &aliasVector);

    int savePKCS12(
        const Alias &alias,
        const PKCS12ShPtr &pkcs,
        const Policy &keyPolicy,
        const Policy &certPolicy);
    int getPKCS12(const Alias &alias, PKCS12ShPtr &pkcs);
    int getPKCS12(const Alias &alias, const Password &keyPass, const Password &certPass, PKCS12ShPtr &pkcs);

    int removeAlias(const Alias &alias);

    int createKeyPairRSA(
        const int size,              // size in bits [1024, 2048, 4096]
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy());

    int createKeyPairDSA(
        const int size,              // size in bits [1024, 2048, 3072, 4096]
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy());

    int createKeyPairECDSA(
        ElipticCurve type,
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy());

    int createKeyAES(
        const int size,              // size in bits [128, 192, 256]
        const Alias &keyAlias,
        const Policy &policyKey = Policy());

    int getCertificateChain(
        const CertificateShPtr &certificate,
        const CertificateShPtrVector &untrustedCertificates,
        const CertificateShPtrVector &trustedCertificates,
        bool useTrustedSystemCertificates,
        CertificateShPtrVector &certificateChainVector);

    int getCertificateChain(
        const CertificateShPtr &certificate,
        const AliasVector &untrustedCertificates,
        const AliasVector &trustedCertificates,
        bool useTrustedSystemCertificates,
        CertificateShPtrVector &certificateChainVector);

    int createSignature(
        const Alias &privateKeyAlias,
        const Password &password,           // password for private_key
        const RawBuffer &message,
        const CryptoAlgorithm &cAlgorithm,
        RawBuffer &signature);

    int verifySignature(
        const Alias &publicKeyOrCertAlias,
        const Password &password,           // password for public_key (optional)
        const RawBuffer &message,
        const RawBuffer &signature,
        const CryptoAlgorithm &cAlgorithm);

    int ocspCheck(const CertificateShPtrVector &certificateChain, int &ocspCheck);

    int setPermission(const Alias &alias, const Label &accessor, PermissionMask permissionMask);

    int encrypt(const CryptoAlgorithm &algo,
                const Alias &keyAlias,
                const Password &password,
                const RawBuffer& plain,
                RawBuffer& encrypted);

    int decrypt(const CryptoAlgorithm &algo,
                const Alias &keyAlias,
                const Password &password,
                const RawBuffer& encrypted,
                RawBuffer& decrypted);

protected:
    int saveBinaryData(
        const Alias &alias,
        DataType dataType,
        const RawBuffer &rawData,
        const Policy &policy);

    int getBinaryData(
        const Alias &alias,
        DataType sendDataType,
        const Password &password,
        DataType &recvDataType,
        RawBuffer &rawData);

    int getBinaryDataAliasVector(
        DataType sendDataType,
        AliasVector &aliasVector);

    int createKeyPair(
        const KeyType key_type,
        const int     additional_param, // key size for [RSA|DSA], elliptic curve type for ECDSA
        const Alias  &privateKeyAlias,
        const Alias  &publicKeyAlias,
        const Policy &policyPrivateKey,
        const Policy &policyPublicKey);

    int crypt(EncryptionCommand command,
              const CryptoAlgorithm &algo,
              const Alias &keyAlias,
              const Password &password,
              const RawBuffer& input,
              RawBuffer& output);

    int m_counter;
    CKM::ServiceConnection m_storageConnection;
    CKM::ServiceConnection m_ocspConnection;
    CKM::ServiceConnection m_encryptionConnection;
};

} // namespace CKM

