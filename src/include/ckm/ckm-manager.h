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
#include <vector>
#include <memory>

#include <ckm/ckm-certificate.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-key.h>
#include <ckm/ckm-type.h>

// Central Key Manager namespace
namespace CKM {

class Manager;
typedef std::shared_ptr<Manager> ManagerShPtr;

class Manager {
public:
    virtual ~Manager(){}

    virtual int saveKey(const Alias &alias, const KeyShPtr &key, const Policy &policy) = 0;
    virtual int saveCertificate(const Alias &alias, const CertificateShPtr &cert, const Policy &policy) = 0;

    /*
     * Data must be extractable. If you set extractable bit to false funciton will
     * return ERROR_INPUT_PARAM.
     */
    virtual int saveData(const Alias &alias, const RawBuffer &data, const Policy &policy) = 0;

    virtual int removeKey(const Alias &alias) = 0;
    virtual int removeCertificate(const Alias &alias) = 0;
    virtual int removeData(const Alias &alias) = 0;

    virtual int getKey(const Alias &alias, const Password &password, KeyShPtr &key) = 0;
    virtual int getCertificate(
        const Alias &alias,
        const Password &password,
        CertificateShPtr &certificate) = 0;
    virtual int getData(const Alias &alias, const Password &password, RawBuffer &data) = 0;

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

    virtual int getCertificateChain(
        const CertificateShPtr &certificate,
        const CertificateShPtrVector &untrustedCertificates,
        CertificateShPtrVector &certificateChainVector) = 0;

    virtual int getCertificateChain(
        const CertificateShPtr &certificate,
        const AliasVector &untrustedCertificates,
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

    virtual int allowAccess(const std::string &alias, const std::string &accessor, AccessRight granted) = 0;
    virtual int denyAccess(const std::string &alias, const std::string &accessor) = 0;


    static ManagerShPtr create();
//    static ManagerShPtr getManager(int uid); // TODO
};

/*
// Asynchronous interface to Central Key Manager. This implementation uses
// internal thread for connection.
class ManagerAsync {
public:
    class ManagerAsyncImpl;

    // Observer will observer custom operation.
    struct Observer {
        // Error callback - all errors
		// ERROR_API_NOT_SUPPORTED,
		// ERROR_API_CONNECTION_LOST,
		// ERROR_API_PARSING_ERROR,
		// ERROR_API_ALIAS_UNKNOWN
        virtual void ReceivedError(int error, const std::string &errormsg);

        // This will return data
        virtual void ReceivedKey(Key && key) {}
        virtual void ReceivedCertificate(Certificate && certificate) {}
        virtual void ReceivedKeyAliasVector(AliasVector && aliasVector) {}
        virtual void ReceivedCertificateAliasVector(AliasVector && aliasVector) {}

        // This callbacks will confirm successful operation
        virtual void ReceivedSaveKey() {}
        virtual void ReceivedSaveCertificate() {}
        virtual void ReceivedRemovedKey() {}
        virtual void ReceivedRemovedCertificate() {}

        // Added By Dongsun Lee
        virtual void ReceivedData(RawBuffer && data) {}
        virtual void ReceivedDataAliasVector(AliasVector && aliasVector) {}

        // This callbacks will confirm successful operation
        virtual void ReceivedSaveData() {}
        virtual void ReceivedRemovedData() {}
        virtual void ReceivedCreateKeyPairRSA() {}
		virtual void ReceivedCreateKeyPairECDSA() {}
        virtual void ReceivedCreateSignature(RawBuffer && signature) {}

        // TODO: describe status
        virtual void ReceivedVerifySignature() {}
        // TODO: describe status
        // Do we need some chain of the certificate?
        virtual void ReceivedVerifyCertificate() {}

		virtual void ReceivedGetCertiticateChain(CertificateShPtrVector &&certificateVector) {}
		virtual void ReceivedStrictCACheck();
		virtual void ReceivedOCSPCheck();

		virtual ~Observer() {}
    };

    ManagerAsync();
    ManagerAsync(const ManagerAsync &);
    ManagerAsync(ManagerAsync &&);
    ManagerAsync& operator=(const ManagerAsync &);
    ManagerAsync& operator=(ManagerAsync &&);
    virtual ~ManagerAsync();

    // observer will be destroyed after use
    void saveKey(Observer *observer, const Alias &alias, const Key &key, const Policy &policy);
    void saveCertificate(Observer *observer, const Alias &alias, const Certificate &cert, const Policy &policy);

    void removeKey(Observer *observer, const Alias &alias);
    void removeCertificate(Observer *observer, const Alias &alias);

    void requestKey(Observer *observer, const Alias &alias);
    void requestCertificate(Observer *observer, const Alias &alias);

    // This will extract list of all Keys and Certificates in Key Store
    void requestKeyAliasVector(Observer *observer);         // send request for list of all keys that application/user may use
    void requestCertificateAliasVector(Observer *observer); // send request for list of all certs that application/user may use

    // Added By Dongsun Lee
    void saveData(Observer *observer, const Alias &alias, const RawBuffer &data, const Policy &policy);
    void removeData(Observer *observer, const Alias &alias);
    void requestData(Observer *observer, const Alias &alias);
    void requestDataAliasVector(Observer *observer);  // send request for list of all data that application/user may use
    void createKeyPairRSA(Observer *observer, const Alias &privateKeyAlias, const Alias &publicKeyAlias, const int &size, const Policy &policy);
	void createKeyPairECDSA(Observer *observer, const Alias &privateKeyAlias, const Alias &publicKeyAlias, ECType type, const int &size, const Policy &policy);
    void createSignature(Observer *observer, const Alias &privateKeyAlias, const RawBuffer &password, const RawBuffer &message);
    void verifySignature(Observer *observer, const Alias &publicKeyOrCertAlias, const RawBuffer &password, const RawBuffer &message, const RawBuffer &signature);

    // Should we use also certificates stored by user in Certral Key Manager?
    // Sometimes we may want to verify certificate without OCSP (for example we are installing side-loaded app and network is not working).
    void verifyCertificate(Observer *observer, const Certificate &certificate, const CertificateShPtrVector &untrusted, const bool ocspCheck, const bool strictCaFlagCheck);

	void createKeyPairRSA(
			Observer *observer,
			const int size,              // size in bits [1024, 2048, 4096]
			const Alias &privateKeyAlias,
			const Alias &publicKeyAlias,
			const Policy &policyPrivateKey = Policy(),
			const Policy &policyPublicKey = Policy());

	void createKeyPairECDSA(
			Observer *observer,
			const Key::ECType type,
			const Alias &privateKeyAlias,
			const Alias &publicKeyAlias,
			const Policy &policyPrivateKey = Policy(),
			const Policy &policyPublicKey = Policy());

	// this fuction will return chains of certificates and check it with openssl
	// status : OK, INCOMPLETE_CHAIN, VERIFICATION_FAILED
	void getCertiticateChain(
			const Certificate &certificate,
			const CertificateShPtrVector &untrustedCertificates);

	void getCertificateChain(
			const Certificate &certificate,
			const AliasVector &untrustedCertificates);

	void strictCACheck(const CertificateShPtrVector &certificateVector);

	// This function will check all certificates in chain except Root CA.
	void ocspCheck(const CertificateShPtrVector &certificateChainVector);

private:
    ConnectionAsyncImpl *m_impl;
};

class ManagerAsyncThread : public ManagerAsync {
public:
    ManagerAsyncThread();
	ManagerAsyncThread(int uid); // connect to database related to uid
    ManagerAsyncThread(const ConnectionAsyncThread &);
    ManagerAsyncThread(ConnectionAsyncThread &&);
    ManagerAsyncThread& operator=(const ConnectionAsyncThread &);
    ManagerAsyncThread& operator=(ConnectionAsyncThread &&);
    virtual ~ConnectionAsyncThread() {}
};
*/
// Out of scope
/*
class ManagerAsyncNoThread : public ManagerAsync {
public:
    ManagerAsyncNoThread();
    ManagerAsyncNoThread(const ConnectionAsyncNoThread &);
    ManagerAsyncNoThread(ConnectionAsyncNoThread &&);
    ManagerAsyncNoThread& operator=(const ConnectionAsyncNoThread &);
    ManagerAsyncNoThread& operator=(ConnectionAsyncNoThread &&);
    virtual ~ConnecitonAsyncNoThread() {}

    int getDesc();          // extract descriptor number
    int processDesc();      // send request and receive data from central key manager
};
*/

} // namespace CKM

