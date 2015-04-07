/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        ckm-manager.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Main header file for client library.
 */
#pragma once

#include <string>
#include <memory>

#include <ckm/ckm-certificate.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-key.h>
#include <ckm/ckm-pkcs12.h>
#include <ckm/ckm-type.h>

// Central Key Manager namespace
namespace CKM {

class Manager;
typedef std::shared_ptr<Manager> ManagerShPtr;

class KEY_MANAGER_API Manager {
public:
    virtual ~Manager(){}

    virtual int saveKey(const Alias &alias, const KeyShPtr &key, const Policy &policy) = 0;
    virtual int saveCertificate(const Alias &alias, const CertificateShPtr &cert, const Policy &policy) = 0;
    virtual int savePKCS12(
            const Alias &alias,
            const PKCS12ShPtr &pkcs,
            const Policy &keyPolicy,
            const Policy &certPolicy) = 0;

    /*
     * Data must be extractable. If you set extractable bit to false function will
     * return ERROR_INPUT_PARAM.
     */
    virtual int saveData(const Alias &alias, const RawBuffer &data, const Policy &policy) = 0;

    virtual int removeAlias(const Alias &alias) = 0;

    virtual int getKey(const Alias &alias, const Password &password, KeyShPtr &key) = 0;
    virtual int getCertificate(
        const Alias &alias,
        const Password &password,
        CertificateShPtr &certificate) = 0;
    virtual int getData(const Alias &alias, const Password &password, RawBuffer &data) = 0;
    virtual int getPKCS12(const Alias &alias, PKCS12ShPtr &pkcs) = 0;
    virtual int getPKCS12(
        const Alias &alias,
        const Password &keyPass,
        const Password &certPass,
        PKCS12ShPtr &pkcs) = 0;

    // send request for list of all keys/certificates/data that application/user may use
    virtual int getKeyAliasVector(AliasVector &aliasVector) = 0;
    virtual int getCertificateAliasVector(AliasVector &aliasVector) = 0;
    virtual int getDataAliasVector(AliasVector &aliasVector) = 0;

    virtual int createKeyPairRSA(
        const int size,              // size in bits [1024, 2048, 4096]
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy()) = 0;

    virtual int createKeyPairDSA(
        const int size,              // size in bits [1024, 2048, 3072, 4096]
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy()) = 0;

    virtual int createKeyPairECDSA(
        const ElipticCurve type,
        const Alias &privateKeyAlias,
        const Alias &publicKeyAlias,
        const Policy &policyPrivateKey = Policy(),
        const Policy &policyPublicKey = Policy()) = 0;

    virtual int createKeyAES(
        const int size,              // size in bits [128, 192, 256]
        const Alias &keyAlias,
        const Policy &policyKey = Policy()) = 0;

    virtual int getCertificateChain(
        const CertificateShPtr &certificate,
        const CertificateShPtrVector &untrustedCertificates,
        const CertificateShPtrVector &trustedCertificates,
        bool useTrustedSystemCertificates,
        CertificateShPtrVector &certificateChainVector) = 0;

    virtual int getCertificateChain(
        const CertificateShPtr &certificate,
        const AliasVector &untrustedCertificates,
        const AliasVector &trustedCertificates,
        bool useTrustedSystemCertificates,
        CertificateShPtrVector &certificateChainVector) = 0;

    virtual int createSignature(
        const Alias &privateKeyAlias,
        const Password &password,           // password for private_key
        const RawBuffer &message,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding,
        RawBuffer &signature) = 0;

    virtual int verifySignature(
        const Alias &publicKeyOrCertAlias,
        const Password &password,           // password for public_key (optional)
        const RawBuffer &message,
        const RawBuffer &signature,
        const HashAlgorithm hash,
        const RSAPaddingAlgorithm padding) = 0;

    // This function will check all certificates in chain except Root CA.
    // This function will delegate task to service. You may use this even
    // if application does not have permission to use network.
    virtual int ocspCheck(const CertificateShPtrVector &certificateChainVector, int &ocspStatus) = 0;

    virtual int setPermission(const Alias &alias, const Label &accessor, PermissionMask permissionMask) = 0;

    virtual int encrypt(const CryptoAlgorithm &algo,
                        const Alias &keyAlias,
                        const Password &password,
                        const RawBuffer& plain,
                        RawBuffer& encrypted) = 0;

    virtual int decrypt(const CryptoAlgorithm &algo,
                        const Alias &keyAlias,
                        const Password &password,
                        const RawBuffer& encrypted,
                        RawBuffer& decrypted) = 0;

    static ManagerShPtr create();
//    static ManagerShPtr getManager(int uid); // TODO
};

} // namespace CKM

