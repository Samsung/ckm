#pragma once

#include <iostream>
#include <generic-key.h>
#include <certificate-impl.h>
#include <ckm/ckm-type.h>
#include <vector>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <dpl/exception.h>

#define DEV_HW_RANDOM_FILE	"/dev/hwrng"
#define DEV_URANDOM_FILE	"/dev/urandom"

#define EVP_SUCCESS	1	// DO NOTCHANGE THIS VALUE
#define EVP_FAIL	0	// DO NOTCHANGE THIS VALUE

#define CKM_CRYPTO_INIT_SUCCESS 1
#define CKM_CRYPTO_CREATEKEY_SUCCESS 2
#define CKM_CREATE_SIGNATURE_SUCCESS 3
#define CKM_VERIFY_SIGNATURE_SUCCESS 4
#define CKM_VERIFY_CHAIN_SUCCESS 5
#define NOT_DEFINED -1

namespace CKM {

 // typedef std::vector<unsigned char> RawData; this must be defined in common header.
 // This is internal api so all functions should throw exception on errors.
class CryptoService {
 public:
     CryptoService();
     virtual ~CryptoService();

     class Exception {
     	public:
     	     DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        	 DECLARE_EXCEPTION_TYPE(Base, Crypto_internal);
     	     DECLARE_EXCEPTION_TYPE(Base, opensslError);
     };

     // During initialization, FIPS_MODE and the antropy source are set.
     // And system certificates are loaded in the memory during initialization.
     //    FIPS_MODE - ON, OFF(Default)
     //    antropy source - /dev/random,/dev/urandom(Default)
     static int initialize();

     static int createKeyPairRSA(const int size,      // size in bits [1024, 2048, 4096]
                         GenericKey &createdPrivateKey,  // returned value ==> Key &createdPrivateKey,
                         GenericKey &createdPublicKey);  // returned value ==> Key &createdPublicKey

     static int createKeyPairECDSA(ElipticCurve type1,
    		 	 	 	 GenericKey &createdPrivateKey,  // returned value
    		 	 	 	 GenericKey &createdPublicKey);  // returned value

     int createSignature(const GenericKey &privateKey,
                         const RawBuffer &message,
                         const HashAlgorithm hashAlgo,
                         const RSAPaddingAlgorithm padAlgo,
                         RawBuffer &signature);

     int verifySignature(const GenericKey &publicKey,
                         const RawBuffer &message,
                         const RawBuffer &signature,
                         const HashAlgorithm hashAlgo,
                         const RSAPaddingAlgorithm padAlgo);

     int verifyCertificateChain(const CertificateImpl &certificate,
 	                    const CertificateImplVector &untrustedCertificates,
 	                    const CertificateImplVector &userTrustedCertificates,
 	                   CertificateImplVector &certificateChainVector);

 private:
     std::vector<X509 *> verifyCertChain(X509 *cert,
		     std::vector<X509 *> &trustedCerts,
		     std::vector<X509 *> &userTrustedCerts,
		     std::vector<X509 *> &untrustedchain);

    bool hasValidCAFlag(std::vector<X509 *> &certChain);
};
}


