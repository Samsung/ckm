#pragma once

#include <iostream>

#include <client-key-impl.h>
#include <client-certificate-impl.h>
#include <ckm/key-manager.h>
#include <ckm/ckm-type.h>
#include <string.h>
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

#define DEV_RANDOM_FILE	"/dev/random"

#define EVP_SUCCESS	1	// DO NOTCHANGE THIS VALUE
#define EVP_FAIL	0	// DO NOTCHANGE THIS VALUE

#define CKM_CRYPTO_CTX_ERROR 2
#define CKM_CRYPTO_PKEYINIT_ERROR 3
#define CKM_CRYPTO_PKEYSET_ERROR 4
#define CKM_CRYPTO_PKEYGEN_ERROR 5
#define CKM_CRYPTO_CREATEKEY_SUCCESS 6
#define CKM_CRYPTO_KEYGEN_ERROR 7
#define CKM_SIG_GEN_ERROR 8
#define CKM_CRYPTO_NOT_SUPPORT_ALGO_ERROR 9
#define CKM_SIG_VERIFY_OPER_ERROR 10
#define CKM_CRYPTO_NOT_SUPPORT_KEY_TYPE 11
#define CKM_CRYPTO_INIT_ERROR 12
#define CKM_CRYPTO_INIT_SUCCESS 13

namespace CKM {

 // typedef std::vector<unsigned char> RawData; this must be defined in common header.
 // This is internal api so all functions should throw exception on errors.
class CryptoService {
 public:
     CryptoService();
     virtual ~CryptoService();

     // During initialization, FIPS_MODE and the antropy source are set.
     // And system certificates are loaded in the memory during initialization.
     //    FIPS_MODE - ON, OFF(Default)
     //    antropy source - /dev/random,/dev/urandom(Default)
     static int initalize();

     int createKeyPairRSA(const int size,      // size in bits [1024, 2048, 4096]
                         KeyImpl &createdPrivateKey,  // returned value ==> Key &createdPrivateKey,
                         KeyImpl &createdPublicKey);  // returned value ==> Key &createdPublicKey

     int createKeyPairECDSA(const Key::ECType type1,
    		 	 	 	 KeyImpl &createdPrivateKey,  // returned value
    		 	 	 	 KeyImpl &createdPublicKey);  // returned value

     int createSignature(const KeyImpl &privateKey,
                         const RawBuffer &message,
                         const HashAlgorithm hashAlgo,
                         const RSAPaddingAlgorithm padAlgo,
                         RawBuffer &signature);

     int verifySignature(const KeyImpl &publicKey,
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


