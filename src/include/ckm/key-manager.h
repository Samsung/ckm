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
 * @file        key-manager.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Main header file for client library.
 */
#pragma once

#include <string>
#include <vector>
#include <memory>

#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>

// Central Key Manager namespace
namespace CKM {

// used by login manager to unlock user data with global password
// [CR] too generic name for class. maybe UserDataControl?
// It's in name space KeyStore so I don't see any problem but
class Control
{
public:
    Control();
    // decrypt user key with password
    int unlockUserKey(const std::string &user, const RawData &password) const;

    // remove user key from memory
    int lockUserKey(const std::string &user) const;

    // remove user data from Store and erase key used for encryption
    int removeUserData(const std::string &user) const;

    // change password for user
    int changeUserPassword(const std::string &user, const RawData &oldPassword, const RawData &newPassword) const;

	// This is work around for security-server api - resetPassword that may be called without passing oldPassword.
	// This api should not be supported on tizen 3.0
	// User must be already logged in and his DKEK is already loaded into memory in plain text form.
	// The service will use DKEK in plain text and encrypt it in encrypted form (using new password).
	int resetUserPassword(const std::string &user, const RawData &newPassword) const;

    virtual ~Control();
private:
    class ControlImpl;
    std::shared_ptr<ControlImpl> m_impl;
};

class Key {
public:
    enum class ECType : unsigned int {
        prime192v1
          // TODO
    };

    Key();
    Key(const RawData &rawData, KeyType type, const RawData &password = RawData()); // Import key
    Key(const Key &key);
    Key& operator=(const Key &key);
    virtual ~Key();

    bool empty() const;
    KeyType getType() const;
    int getSize() const;
	ECType getCurve() const;
    RawData getKey() const;
    KeyImpl* getImpl() const;

private:
    std::shared_ptr<KeyImpl> m_impl;
};

class Certificate {
public:
    enum class FingerprintType : unsigned int {
        FINGERPRINT_MD5,
        FINGERPRINT_SHA1,
        FINGERPRINT_SHA256
    };

    enum class Format : unsigned int {
        FORM_BASE64,
        FORM_DER
    };

    Certificate();
    Certificate(const RawData &rawData, Format format);
	Certificate(const Certificate &certificate);
	Certificate& operator=(const Certificate &certificate);

	bool empty() const;

//  Key getKey() const;

    // This function  will return openssl struct X509*.
    void *getX509();
    RawData getDER() const;
    CertificateImpl* getImpl();

//    // *** standard certificate operation begin ***
//    RawData getDER() const;
//    bool isSignedBy(const Certificate &parent) const;
//    RawData getFingerprint(FingerprintType type) const;
//	bool isCA() const;
//    // *** standard certificate operation end ***
private:
    std::shared_ptr<CertificateImpl> m_impl;
};

typedef std::vector<Certificate> CertificateVector;

/*
class Pkcs12 {
public:
	Pkcs12();
	Pkcs12(const RawData &rawData, const RawData &password = RawData());

	Pkcs12(const Pkcs12 &pkcs);
	Pkcs12(Pkcs12 &&pkcs);
	Pkcs12& operator=(const Pkcs12 &pkcs);
	Pkcs12& operator=(Pkcs12 &&pkcs);

	Key getKey(const RawData &password = RawData());
	Certificate getCertificate(); // this is connected with Key

	// check the API in openssl and translate it 1 to 1.

	CertificateVector getCertificateVector();

	bool empty();
	virtual ~Pkcs12();
private:
	class Pkcs12Impl;
	Pkcs12Impl *m_impl;
};
*/

class Manager {
public:
    Manager();
//	Manager(int uid);   // connect to database related with uid
    Manager(const Manager &connection) = delete;
    Manager(Manager &&connection) = delete;
    Manager operator=(const Manager &connection) = delete;
    Manager operator=(Manager && connection) = delete;
    virtual ~Manager();

    int saveKey(const Alias &alias, const Key &key, const Policy &policy);
    int saveCertificate(const Alias &alias, const Certificate &cert, const Policy &policy);

    int removeKey(const Alias &alias);
    int removeCertificate(const Alias &alias);

    int getKey(const Alias &alias, const RawData &password, Key &key);
    int getCertificate(
            const Alias &alias,
            const RawData &password,
            Certificate &certificate);

    // This will extract list of all Keys and Certificates in Key Store
    int requestKeyAliasVector(AliasVector &alias);          // send request for list of all keys that application/user may use
//    int requestCertificateAliasVector(AliasVector &alias);  // send request for list of all certs that application/user may use

    // Added By Dongsun Lee
    int saveData(const Alias &alias, const RawData &data, const Policy &policy);
    int removeData(const Alias &alias);
    int getData(const Alias &alias, const RawData &password, RawData &data);
//    int requestDataAliasVector(AliasVector &alias);
//
//    int createKeyPairRSA(
//			const int size,              // size in bits [1024, 2048, 4096]
//			const Alias &privateKeyAlias,
//			const Alias &publicKeyAlias,
//			const Policy &policyPrivateKey = Policy(),
//			const Policy &policyPublicKey = Policy());
//
//	int createKeyPairECDSA(
//			const Key::ECType type,
//			const Alias &privateKeyAlias,
//			const Alias &publicKeyAlias,
//			const Policy &policyPrivateKey = Policy(),
//			const Policy &policyPublicKey = Policy());
//
//	int createSignature(
//			const Alias &privateKeyAlias,
//			const RawData &password,           // password for private_key
//			const RawData &message,
//			HashAlgorith hash,
//			RSAPaddingAlgorithm padding,
//			RawData &signature);
//
//	int verifySignature(
//			const Alias &publicKeyOrCertAlias,
//			const RawData &password,           // password for public_key (optional)
//			const RawData &message,
//			const RawData &signature,
//			HashAlgorithm hash,
//            RSAPaddingAlgorithm padding);
//
//	// this fuction will return chains of certificates and check it with openssl
//	// status : OK, INCOMPLETE_CHAIN, VERIFICATION_FAILED
//	int getCertiticateChain(
//			const Certificate &certificate,
//			const CertificateVector &untrustedCertificates,
//			CertificateVector &certificateChainVector);
//
//	int getCertificateChain(
//			const Certificate &certificate,
//			const AliasVector &untrustedCertificates,
//			CertificateVector &certificateChainVector);
//
//	int strictCACheck(const CertificateVector &certificateVector);
//
//	// This function will check all certificates in chain except Root CA.
//	int ocspCheck(const CertificateVector &certificateChainVector);

private:
    class ManagerImpl;
    std::shared_ptr<ManagerImpl> m_impl;
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
        virtual void ReceivedData(RawData && data) {}
        virtual void ReceivedDataAliasVector(AliasVector && aliasVector) {}

        // This callbacks will confirm successful operation
        virtual void ReceivedSaveData() {}
        virtual void ReceivedRemovedData() {}
        virtual void ReceivedCreateKeyPairRSA() {}
		virtual void ReceivedCreateKeyPairECDSA() {}
        virtual void ReceivedCreateSignature(RawData && signature) {}

        // TODO: describe status
        virtual void ReceivedVerifySignature() {}
        // TODO: describe status
        // Do we need some chain of the certificate?
        virtual void ReceivedVerifyCertificate() {}

		virtual void ReceivedGetCertiticateChain(CertificateVector &&certificateVector) {}
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
    void saveData(Observer *observer, const Alias &alias, const RawData &data, const Policy &policy);
    void removeData(Observer *observer, const Alias &alias);
    void requestData(Observer *observer, const Alias &alias);
    void requestDataAliasVector(Observer *observer);  // send request for list of all data that application/user may use
    void createKeyPairRSA(Observer *observer, const Alias &privateKeyAlias, const Alias &publicKeyAlias, const int &size, const Policy &policy);
	void createKeyPairECDSA(Observer *observer, const Alias &privateKeyAlias, const Alias &publicKeyAlias, ECType type, const int &size, const Policy &policy);
    void createSignature(Observer *observer, const Alias &privateKeyAlias, const RawData &password, const RawData &message);
    void verifySignature(Observer *observer, const Alias &publicKeyOrCertAlias, const RawData &password, const RawData &message, const RawData &signature);

    // Should we use also certificates stored by user in Certral Key Manager?
    // Sometimes we may want to verify certificate without OCSP (for example we are installing side-loaded app and network is not working).
    void verifyCertificate(Observer *observer, const Certificate &certificate, const CertificateVector &untrusted, const bool ocspCheck, const bool strictCaFlagCheck);

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
			const CertificateVector &untrustedCertificates);

	void getCertificateChain(
			const Certificate &certificate,
			const AliasVector &untrustedCertificates);

	void strictCACheck(const CertificateVector &certificateVector);

	// This function will check all certificates in chain except Root CA.
	void ocspCheck(const CertificateVector &certificateChainVector);

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

