#pragma once

#include <string>
#include <vector>
#include <memory>

#include <ckm/errors.h>

// Central Key Manager namespace
namespace CKM {

// used to pass password and raw key data
typedef std::vector<unsigned char> RawData;
typedef std::string Alias;
typedef std::vector<Alias> AliasVector;

struct Policy {
	Policy(const RawData &pass = RawData(), bool extract = true, bool restrict = false)
	  : extractable(extract)
	  , restricted(restrict)
	{}
    RawData password;  // byte array used to encrypt data inside CKM
    bool extractable;  // if true key may be extracted from storage
    bool restricted;   // if true only key owner may see data
};

// used by login manager to unlock user data with global password
// [CR] too generic name for class. maybe UserDataControl?
// It's in name space KeyStore so I don't see any problem but 
class Control
{
public:
    // decrypt user key with password
    int unlockUserKey(const std::string &user, const RawData &password) const;

    // remove user key from memory
    void lockUserKey(const std::string &user);

    // remove user data from Store and erase key used for encryption
    void removeUserData(const std::string &user);

    // change password for user
    int changeUserPassword(const std::string &user, const RawData &oldPassword, const RawData &newPassword) const;
	
	// This is work around for security-server api - resetPassword that may be called without passing oldPassword.
	// This api should not be supported on tizen 3.0
	// User must be already logged in and his DKEK is already loaded into memory in plain text form.
	// The service will use DKEK in plain text and encrypt it in encrypted form (using new password).
	int resetUserPassword(const std::string &user, const RawData &newPassword) const;
private:
    class ControlImpl;
    std::shared_ptr<ControlImpl> m_impl;
};

class Key {
public:
    // [CR] (just asking): is there any AES private/public?
    // No. AES is symetric cypher so there is only one key
    enum class Type : unsigned int {
        KEY_NONE,
        KEY_RSA_PUBLIC,
        KEY_RSA_PRIVATE,
        KEY_ECDSA_PUBLIC,
        KEY_ECDSA_PRIVATE,
        KEY_AES
    };

	enum class ECType : unsigned int {
		prime192v1
		// TODO
	}
	
    enum class Format : unsigned int {
        PEM, DER
    };

    Key();
    Key(const RawData &rawData, Format format, Type type, RawData &password = RawData()); // Import key
    Key(const Key &key);
    Key(Key &&key);
    Key& operator=(const Key &key);
    Key& operator=(Key &&key);
    virtual ~Key(); // This destructor must overwrite memory used by key with some random data.

    // [CR] why is this needed?
    // Default constructor is required by standard containers.
    // Default constructor will create empty Key class.
    bool empty() const;

    // Type of key
    Type getType() const;

    // key size in bits RSA specific
    int getSize() const;
	
	// Eliptic curve type
	ECType getCurve() const;

private:
    class KeyImpl;
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
        PEM,
        DER,
        BASE64_DER      // binary form encoded in BASE64
    };

    Certificate();
    Certificate(const RawData &rawData, int format);
	Certificate(const Certificate &certificate);
	Certificate(Certificate &&certificate);
	Certificate& operator=(const Certificate &certificate);
	Certificate& operator=(Certificate &&certificate);
    
	bool empty() const;

    Key getKey() const;

    // [CR] is this a common principle to leave void* or should we directly return x509 struct and include openssl header here? (just asking)
    // This function  will return openssl struct X509*. We don't want to
    // include all openssl headers in this file so we need to return void
    // or move this function to some other header.
    void *getX509();

    // *** standard certificate operation begin ***
    RawData getDER() const;
    bool isSignedBy(const Certificate &parent) const;
    RawData getFingerprint(FingerprintType type) const;
	bool isCA() const;
    // *** standard certificate operation end ***
private:
    class CertificateImpl;
    std::shared_ptr<CertificateImpl> m_impl;
};

typedef std::vector<Certificate> CertificateVector;

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

class Manager {
public:
    Manager();
	Manager(int uid);   // connect to database related with uid
    Manager(const Manager &connection);
    Manager(Manager &&connection);
    Manager operator=(const Manager &connection);
    Manager operator=(Manager && connection);
    virtual ~Manager();

    int saveKey(const Alias &alias, const Key &key, const Policy &policy);
	// Certificate could not be nonexportable because we must be able to read
	// extension data in the client during validation process.
    int saveCertificate(const Alias &alias, const Certificate &cert, const Policy &policy);

    int removeKey(const Alias &alias);
    int removeCertificate(const Alias &alias);

    int getKey(const Alias &alias, Key &key, RawData &password);
    int getCertificate(const Alias &alias, Certificate &certificate, RawData &password = RawData());

    // This will extract list of all Keys and Certificates in Key Store
    int requestKeyAliasVector(AliasVector &alias);          // send request for list of all keys that application/user may use
    int requestCertificateAliasVector(AliasVector &alias);  // send request for list of all certs that application/user may use

    // Added By Dongsun Lee
    int saveData(const Alias &alias, const RawData &data, const Policy &policy);
    int removeData(const Alias &alias);
    int getData(const Alias &alias, RawData &data, RawData &password = RawData());
    int requestDataAliasVector(AliasVector &alias);

    int createKeyPairRSA(
			const int size,              // size in bits [1024, 2048, 4096]
			const Alias &privateKeyAlias,
			const Alias &publicKeyAlias,
			const Policy &policyPrivateKey = Policy(),
			const Policy &policyPublicKey = Policy());

	int createKeyPairECDSA(
			const Key::ECType type,
			const Alias &privateKeyAlias,
			const Alias &publicKeyAlias,
			const Policy &policyPrivateKey = Policy(),
			const Policy &policyPublicKey = Policy());
    
	int createSignature(
			const Alias &privateKeyAlias,
			const RawData &password,           // password for private_key
			const RawData &message,
			const HashAlgorith hash,
			TODO Padding,
			RawData &signature);
    
	int verifySignature(
			const Alias &publicKeyOrCertAlias,
			const RawData &password,           // password for public_key (optional)
			const RawData &message,
			const RawData &signature,
			const HashAlgorithm,
			TODO Padding);
    
	// this fuction will return chains of certificates and check it with openssl
	// status : OK, INCOMPLETE_CHAIN, VERIFICATION_FAILED
	int getCertiticateChain(
			const Certificate &certificate,
			const CertificateVector &untrustedCertificates,
			CertificateVector &certificateChainVector);
			
	int getCertificateChain(
			const Certificate &certificate,
			const AliasVector &untrustedCertificates,
			CertificateVector &certificateChainVector);
	
	int strictCACheck(const CertificateVector &certificateVector);

	// This function will check all certificates in chain except Root CA.
	int ocspCheck(const CertificateVector &certificateChainVector);
	
private:
    class ManagerImpl;
    std::shared_ptr<ManagerSyncImpl> m_impl;
};

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

