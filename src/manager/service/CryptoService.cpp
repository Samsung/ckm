#include <iostream>
#include <exception>
#include <vector>
#include <fstream>
#include <string.h>
#include <memory>

#include <openssl/x509_vfy.h>
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
#include <openssl/x509v3.h>
#include <openssl/obj_mac.h>
#include <ckm/ckm-error.h>
#include <ckm/ckm-type.h>
#include <generic-key.h>
#include <CryptoService.h>
#include <key-manager-util.h>
#include <assert.h>
#include <dpl/log/log.h>

#define OPENSSL_SUCCESS 1       // DO NOTCHANGE THIS VALUE
#define OPENSSL_FAIL    0       // DO NOTCHANGE THIS VALUE

namespace CKM {

CryptoService::CryptoService(){
}

CryptoService::~CryptoService(){
}



int CryptoService::initialize() {
	int mode = 0;
	int rc = 0;
	int hw_rand_ret = 0, u_rand_ret = 0;

	// try to initialize using ERR_load_crypto_strings and OpenSSL_add_all_algorithms
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	// turn on FIPS_mode
	mode = FIPS_mode();

	if(mode == 0) {
		rc = FIPS_mode_set(1);

		if(rc == 0) {
			LogError("Error in FIPS_mode_set function");
		}
	}

	// initialize entropy
	std::ifstream ifile(DEV_HW_RANDOM_FILE);
	if(ifile.is_open()) {
		u_rand_ret= RAND_load_file(DEV_HW_RANDOM_FILE, 32);
	}
	if(u_rand_ret != 32 ){
		LogError("Error in HW_RAND file load");
		hw_rand_ret = RAND_load_file(DEV_URANDOM_FILE, 32);

		if(hw_rand_ret != 32) {
			LogError("Error in U_RAND_file_load");
			ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in U_RAND_file_load");
		}
	}

	return CKM_CRYPTO_INIT_SUCCESS;
}



int CryptoService::createKeyPairRSA(const int size, // size in bits [1024, 2048, 4096]
		GenericKey &createdPrivateKey,  // returned value
		GenericKey &createdPublicKey)  // returned value
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pparam = NULL;

	// check the parameters of functions
	if(size != 1024 && size !=2048 && size != 4096) {
		LogError("Error in RSA input size");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in RSA input size");
	}

	// check the parameters of functions
	if(&createdPrivateKey == NULL) {
		LogError("Error in createdPrivateKey value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in createdPrivateKey value");
	}

	// check the parameters of functions
	if(&createdPublicKey == NULL) {
		LogError("Error in createdPrivateKey value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in createdPublicKey value");
	}

	Try {
		if(!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))) {
			LogError("Error in EVP_PKEY_CTX_new_id function !!");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_new_id function !!");
		}

		if(EVP_PKEY_keygen_init(ctx) <= 0) {
			LogError("Error in EVP_PKEY_keygen_init function !!");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_keygen_init function !!");
		}

		if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,size) <= 0) {
			LogError("Error in EVP_PKEY_CTX_set_rsa_keygen_bits function !!");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_rsa_keygen_bits function !!");
		}

		if(!EVP_PKEY_keygen(ctx, &pkey)) {
			LogError("Error in EVP_PKEY_keygen function !!");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_keygen function !!");
		}
	} Catch(CryptoService::Exception::opensslError) {
		if(pkey) {
			EVP_PKEY_free(pkey);
		}

		if(pparam) {
			EVP_PKEY_free(pparam);
		}

		if(ctx) {
			EVP_PKEY_CTX_free(ctx);
		}

		ReThrowMsg(CryptoService::Exception::opensslError,"Error in opensslError function !!");
	}

	GenericKey::EvpShPtr ptr(pkey, EVP_PKEY_free); // shared ptr will free pkey

	createdPrivateKey = GenericKey(ptr, KeyType::KEY_RSA_PRIVATE);
	createdPublicKey = GenericKey(ptr, KeyType::KEY_RSA_PUBLIC);

	if(pparam) {
		EVP_PKEY_free(pparam);
	}

	if(ctx) {
		EVP_PKEY_CTX_free(ctx);
	}

	return CKM_CRYPTO_CREATEKEY_SUCCESS;
}

int CryptoService::createKeyPairECDSA(ElipticCurve type,
		GenericKey &createdPrivateKey,  // returned value
		GenericKey &createdPublicKey)  // returned value
{
	int ecCurve = NOT_DEFINED;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pparam = NULL;

	switch(type) {
	case ElipticCurve::prime192v1:
		ecCurve = NID_X9_62_prime192v1;
		break;
	case ElipticCurve::prime256v1:
		ecCurve = NID_X9_62_prime256v1;
		break;
	case ElipticCurve::secp384r1:
		ecCurve = NID_secp384r1;
		break;
	default:
		LogError("Error in EC type");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in EC type");
	}

	// check the parameters of functions
	if(&createdPrivateKey == NULL) {
		LogError("Error in createdPrivateKey value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in createdPrivateKey value");
	}

	// check the parameters of functions
	if(&createdPublicKey == NULL) {
		LogError("Error in createdPrivateKey value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in createdPublicKey value");
	}

	Try {
		/* Create the context for generating the parameters */
		if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
			LogError("Error in EVP_PKEY_CTX_new_id function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_new_id function");
		}

		if(EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx)) {
			LogError("Error in EVP_PKEY_paramgen_init function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_paramgen_init function");
		}

		if(EVP_SUCCESS != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ecCurve)) {
			LogError("Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid function");
		}

		/* Generate parameters */
		if(EVP_SUCCESS != EVP_PKEY_paramgen(pctx, &pparam)) {
			LogError("Error in EVP_PKEY_paramgen function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_paramgen function");
		}

		// Start to generate key
		if(!(kctx = EVP_PKEY_CTX_new(pparam, NULL))) {
			LogError("Error in EVP_PKEY_CTX_new function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_new function");
		}

		if(EVP_SUCCESS != EVP_PKEY_keygen_init(kctx)) {
			LogError("Error in EVP_PKEY_keygen_init function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_keygen_init function");
		}

		/* Generate the key */
		if(EVP_SUCCESS != EVP_PKEY_keygen(kctx, &pkey)) {
			LogError("Error in EVP_PKEY_keygen function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_keygen function");
		}
	} Catch(CryptoService::Exception::opensslError) {
		if(pkey) {
			EVP_PKEY_free(pkey);
		}

		if(pparam) {
			EVP_PKEY_free(pparam);
		}

		if(pctx) {
			EVP_PKEY_CTX_free(pctx);
		}

		if(kctx) {
			EVP_PKEY_CTX_free(kctx);
		}

		ReThrowMsg(CryptoService::Exception::opensslError,"Error in openssl function !!");
	}

	GenericKey::EvpShPtr ptr(pkey, EVP_PKEY_free); // shared ptr will free pkey

	createdPrivateKey = GenericKey(ptr, KeyType::KEY_ECDSA_PRIVATE);
	createdPublicKey = GenericKey(ptr, KeyType::KEY_ECDSA_PUBLIC);

	if(pparam) {
		EVP_PKEY_free(pparam);
	}

	if(pctx) {
		EVP_PKEY_CTX_free(pctx);
	}

	if(kctx) {
		EVP_PKEY_CTX_free(kctx);
	}

	return CKM_CRYPTO_CREATEKEY_SUCCESS;
}

int CryptoService::createSignature(const GenericKey &privateKey,
		const RawBuffer &message,
		const HashAlgorithm hashAlgo,
		const RSAPaddingAlgorithm padAlgo,
		RawBuffer &signature)
{
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int rsa_padding = NOT_DEFINED;
	RawBuffer data;
	const EVP_MD *md_algo = NULL;

	// check the parameters of functions
	if(&privateKey == NULL) {
		LogError("Error in privateKey value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in privateKey value");
	}

	if(&message == NULL) {
		LogError("Error in message value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in message value");
	}

	switch(hashAlgo) {
	case HashAlgorithm::SHA1:
		md_algo = EVP_sha1();
		break;
	case HashAlgorithm::SHA256:
		md_algo = EVP_sha256();
		break;
	case HashAlgorithm::SHA384:
		md_algo = EVP_sha384();
		break;
	case HashAlgorithm::SHA512:
		md_algo = EVP_sha512();
		break;
	default:
		LogError("Error in hashAlgorithm value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in hashAlgorithm value");
	}

	if((privateKey.getType() != KeyType::KEY_RSA_PRIVATE) && (privateKey.getType() != KeyType::KEY_ECDSA_PRIVATE)) {
		LogError("Error in private key type");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in private key type");
	}

	if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
		switch(padAlgo) {
		case RSAPaddingAlgorithm::PKCS1:
			rsa_padding = RSA_PKCS1_PADDING;
			break;
		case RSAPaddingAlgorithm::X931:
			rsa_padding = RSA_X931_PADDING;
			break;
		default:
			LogError("Error in padding Algorithm value");
			ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in padding Algorithm value");
		}
	}

	auto shrPKey = privateKey.getEvpShPtr();

	Try {
		if (NULL == shrPKey.get()) {
			LogError("Error in EVP_PKEY_keygen function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_keygen function");
		}

		// Create the Message Digest Context
		if(!(mdctx = EVP_MD_CTX_create())) {
			LogError("Error in EVP_MD_CTX_create function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_MD_CTX_create function");
		}

		if(EVP_SUCCESS != EVP_DigestSignInit(mdctx, &pctx, md_algo, NULL, shrPKey.get())) {
			LogError("Error in EVP_DigestSignInit function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestSignInit function");
		}

		/* Set padding algorithm */
		if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
			if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
				LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
				ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
			}
		}

		/* Call update with the message */
		char msg[message.size()];
		memcpy(msg, message.data(),message.size());
		if(EVP_SUCCESS != EVP_DigestSignUpdate(mdctx, msg, message.size())) {
			LogError("Error in EVP_DigestSignUpdate function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestSignUpdate function");
		}

		/* Finalize the DigestSign operation */
		/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
		 * signature. Length is returned in slen */
		size_t slen;
		if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
			LogError("Error in EVP_DigestSignFinal function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestSignFinal function");
		}
		/* Allocate memory for the signature based on size in slen */
		unsigned char sig[slen];

		/* Obtain the signature */
		if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx, sig, &slen)) {
			LogError("Error in EVP_DigestSignFinal function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestSignFinal function");
		}

		// Set value to return RawData
		signature.assign(sig, sig+slen);
	} Catch(CryptoService::Exception::opensslError) {
		if(mdctx != NULL) {
			EVP_MD_CTX_destroy(mdctx);
		}

		ReThrowMsg(CryptoService::Exception::opensslError,"Error in openssl function !!");
	}

	if(mdctx != NULL) {
		EVP_MD_CTX_destroy(mdctx);
	}

	return CKM_CREATE_SIGNATURE_SUCCESS;
}

int CryptoService::verifySignature(const GenericKey &publicKey,
		const RawBuffer &message,
		const RawBuffer &signature,
		const HashAlgorithm hashAlgo,
		const RSAPaddingAlgorithm padAlgo)
{
	EVP_PKEY_CTX *pctx = NULL;
	int rsa_padding = NOT_DEFINED;
	const EVP_MD *md_algo;
    int retCode = CKM_API_ERROR_VERIFICATION_FAILED;
    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> mdctx(nullptr, EVP_MD_CTX_destroy);

    if(&publicKey == NULL) {
		LogError("Error in publicKey value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in publicKey value");
	}

	if(&message == NULL) {
		LogError("Error in message value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in message value");
	}

	if(&signature == NULL) {
		LogError("Error in signature value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in signature value");
	}

	switch(hashAlgo) {
	case HashAlgorithm::SHA1:
		md_algo = EVP_sha1();
		break;
	case HashAlgorithm::SHA256:
		md_algo = EVP_sha256();
		break;
	case HashAlgorithm::SHA384:
		md_algo = EVP_sha384();
		break;
	case HashAlgorithm::SHA512:
		md_algo = EVP_sha512();
		break;
	default:
		LogError("Error in hashAlgorithm value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in hashAlgorithm value");
	}

	if((publicKey.getType() != KeyType::KEY_RSA_PUBLIC) && (publicKey.getType() != KeyType::KEY_ECDSA_PUBLIC)) {
		LogError("Error in private key type");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in private key type");
	}

	if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
		switch(padAlgo) {
		case RSAPaddingAlgorithm::PKCS1:
			rsa_padding = RSA_PKCS1_PADDING;
			break;
		case RSAPaddingAlgorithm::X931:
			rsa_padding = RSA_X931_PADDING;
			break;
		default:
			LogError("Error in padding Algorithm value");
			ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in padding Algorithm value");
		}
	}

    auto public_pkey = publicKey.getEvpShPtr();

    if (NULL == public_pkey.get()) {
        LogError("Error in getEvpShPtr function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in getEvpShPtr function");
    }

    /* Create the Message Digest Context */
    mdctx.reset(EVP_MD_CTX_create());

    if(!(mdctx.get())) {
        LogError("Error in EVP_MD_CTX_create function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_MD_CTX_create function");
    }

    if(EVP_SUCCESS != EVP_DigestVerifyInit(mdctx.get(), &pctx, md_algo, NULL, public_pkey.get())) {
        LogError("Error in EVP_DigestVerifyInit function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestVerifyInit function");
    }

    if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding))  {
            LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    if(EVP_SUCCESS != EVP_DigestVerifyUpdate(mdctx.get(), message.data(), message.size()) ) {
        LogError("Error in EVP_DigestVerifyUpdate function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestVerifyUpdate function");
    }

    if(EVP_SUCCESS == EVP_DigestVerifyFinal(mdctx.get(), const_cast<unsigned char*>(signature.data()), signature.size()) ) {
        retCode = CKM_API_SUCCESS;
    } else {
        LogError("Error in EVP_DigestVerifyFinal function");
    }

	return retCode;
}


int CryptoService::verifyCertificateChain(const CertificateImpl &certificate,
		const CertificateImplVector &untrustedCertificates,
		const CertificateImplVector &userTrustedCertificates,
		CertificateImplVector &certificateChainVector) {

	X509 *cert = X509_new();
	X509 *tempCert;
	rawBufferToX509(&cert, certificate.getDER());

	std::vector<X509 *> trustedCerts;
	std::vector<X509 *> userTrustedCerts;
	std::vector<X509 *> untrustedChain;

	STACK_OF(X509) *sysCerts = loadSystemCerts(CKM_SYSTEM_CERTS_PATH);

	// check the parameters of functions
	if(&certificate == NULL) {
		LogError("Error in certificate value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in certificate value");
	}

	// check the parameters of functions
	if(&untrustedCertificates == NULL) {
		LogError("Error in untrustedCertificates value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in untrustedCertificates value");
	}

	// check the parameters of functions
	if(&userTrustedCertificates == NULL) {
		LogError("Error in userTrustedCertificates value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in userTrustedCertificates value");
	}

	// check the parameters of functions
	if(&certificateChainVector == NULL) {
		LogError("Error in certificateChainVector value");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in certificateChainVector value");
	}

	Try {
		while((tempCert = sk_X509_pop(sysCerts)) != NULL) {
			trustedCerts.push_back(tempCert);
		}

		for(unsigned int i=0;i<userTrustedCertificates.size();i++) {
			if((tempCert = X509_new()) == NULL) {
				LogError("Error in X509_new function");
				ThrowMsg(CryptoService::Exception::opensslError, "Error in X509_new function");
			}
			rawBufferToX509(&tempCert, userTrustedCertificates[i].getDER());
			userTrustedCerts.push_back(tempCert);
		}

		for(unsigned int i=0;i<untrustedCertificates.size();i++) {
			if((tempCert = X509_new()) == NULL) {
				LogError("Error in X509_new function");
				ThrowMsg(CryptoService::Exception::opensslError, "Error in X509_new function");
			}
			rawBufferToX509(&tempCert, untrustedCertificates[i].getDER());
			untrustedChain.push_back(tempCert);
		}

		std::vector<X509 *> chain = verifyCertChain(cert, trustedCerts, userTrustedCerts, untrustedChain);

		RawBuffer tmpBuf;
		for(unsigned int i=0;i<chain.size();i++) {
			x509ToRawBuffer(tmpBuf, chain[i]);
			CertificateImpl tmpCertImpl((const RawBuffer)tmpBuf, DataFormat::FORM_DER);
			certificateChainVector.push_back(tmpCertImpl);
		}
	} Catch(CryptoService::Exception::opensslError) {
		if(cert != NULL) {
			X509_free(cert);
		}

		for(unsigned int i=0;i<trustedCerts.size();i++) {
			if(trustedCerts[i] != NULL) {
				X509_free(trustedCerts[i]);
			}
		}

		for(unsigned int i=0;i<untrustedChain.size();i++) {
			if(untrustedChain[i] != NULL) {
				X509_free(untrustedChain[i]);
			}
		}

		for(unsigned int i=0;i<userTrustedCerts.size();i++) {
			if(userTrustedCerts[i] != NULL) {
				X509_free(userTrustedCerts[i]);
			}
		}
		ReThrowMsg(CryptoService::Exception::opensslError,"Error in openssl function !!");
	}

	if(cert != NULL) {
		X509_free(cert);
	}

	for(unsigned int i=0;i<trustedCerts.size();i++) {
		if(trustedCerts[i] != NULL) {
			X509_free(trustedCerts[i]);
		}
	}

	for(unsigned int i=0;i<untrustedChain.size();i++) {
		if(untrustedChain[i] != NULL) {
			X509_free(untrustedChain[i]);
		}
	}

	for(unsigned int i=0;i<userTrustedCerts.size();i++) {
		if(userTrustedCerts[i] != NULL) {
			X509_free(userTrustedCerts[i]);
		}
	}

	return CKM_VERIFY_CHAIN_SUCCESS;
}

/*
 * truestedCerts means the system certificate list stored in system securely.
 * return : std::vector<X509 *> certChain; the order is user cert, middle ca certs, and root ca cert.
 */

std::vector<X509 *> CryptoService::verifyCertChain(X509 *cert,
		std::vector<X509 *> &trustedCerts,
		std::vector<X509 *> &userTrustedCerts,
		std::vector<X509 *> &untrustedchain){

	std::vector<X509 *> certChain;
	X509_STORE *tstore = X509_STORE_new();
	STACK_OF(X509) *uchain = sk_X509_new_null();
	std::vector<X509 *>::iterator iVec_it;

	for(iVec_it = trustedCerts.begin(); iVec_it != trustedCerts.end(); iVec_it++) {
		X509_STORE_add_cert(tstore, *iVec_it);
	}
	for(iVec_it = userTrustedCerts.begin(); iVec_it != userTrustedCerts.end(); iVec_it++) {
		X509_STORE_add_cert(tstore, *iVec_it);
	}

	for(iVec_it = untrustedchain.begin(); iVec_it != untrustedchain.end(); iVec_it++) {
		sk_X509_push(uchain, *iVec_it);
	}

	// Create the context to verify the certificate.
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();

	// Initial the store to verify the certificate.
	X509_STORE_CTX_init(ctx, tstore, cert, uchain);

	int verified = X509_verify_cert(ctx);

	if(verified == OPENSSL_SUCCESS) {
		STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
		X509 *cert;
		while((cert = sk_X509_pop(chain))) {
			certChain.insert(certChain.begin(),cert);
		}
	}

	X509_STORE_CTX_cleanup(ctx);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(tstore);
	sk_X509_free(uchain);
	ctx = NULL;
	tstore = NULL;
	uchain = NULL;

	if(verified != OPENSSL_SUCCESS) {
		LogError("Error in verifying certification chain");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in verifying certification chain");
	}

	return certChain;
}

bool CryptoService::hasValidCAFlag(std::vector<X509 *> &certChain) {
	// KeyUsage if present should allow cert signing;
	// If basicConstraints says not a CA then say so.

	X509 *cert = NULL;
	int isCA;

	if(certChain.size() < 2) // certChain should have more than 2 certs.
		return false;

	std::vector<X509 *>::iterator it;
	for(it = certChain.begin()+1; it != certChain.end(); it++) { // start from the second cert
		cert = *it;
		isCA = X509_check_ca(cert);
		// For MDPP compliance.
		// if it returns 1, this means that the cert has the basicConstraints and CAFlag=true.
		// X509_check_ca can return 0(is not CACert), 1(is CACert), 3, 4, 5(may be CACert).
		if(isCA != 1) {
			return false;
		}
	}

	return true;
}
}
