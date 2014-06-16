#include <iostream>
#include <exception>
#include <vector>
#include <openssl/x509_vfy.h>
#include <string.h>
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
#include <ckm/ckm-type.h>
#include <key-rsa.h>
#include <key-ecdsa.h>
#include <CryptoService.h>
#include <key-manager-util.h>

#include <dpl/log/log.h>

#define OPENSSL_SUCCESS 1       // DO NOTCHANGE THIS VALUE
#define OPENSSL_FAIL    0       // DO NOTCHANGE THIS VALUE

namespace CKM {

CryptoService::CryptoService(){
}

CryptoService::~CryptoService(){
}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
//void to_string_rsa_private_key(RSA *pkey, unsigned char **derPrivateKey, int *length) {
//	unsigned char *ucTmp;
//	*length = i2d_RSAPrivateKey(pkey, NULL);
//	*derPrivateKey = (unsigned char *)malloc(*length);
//	ucTmp = *derPrivateKey;
//	i2d_RSAPrivateKey(pkey, &ucTmp);
//}

//void to_string_rsa_public_key(RSA *pkey, unsigned char **derPublicKey, int *length) {
//	unsigned char *ucTmp;
//	*length = i2d_RSA_PUBKEY(pkey, NULL);
//	*derPublicKey = (unsigned char *)malloc(*length);
//	ucTmp = *derPublicKey;
//	i2d_RSA_PUBKEY(pkey, &ucTmp);
//}

//void to_string_ec_private_key(EC_KEY *pkey, unsigned char **derPrivateKey, int *length) {
//	unsigned char *ucTmp;
//	*length = i2d_ECPrivateKey(pkey, NULL);
//	*derPrivateKey = (unsigned char *)malloc(*length);
//	ucTmp = *derPrivateKey;
//	i2d_ECPrivateKey(pkey, &ucTmp);
//}
//
//void to_string_ec_public_key(EC_KEY *pkey, unsigned char **derPublicKey, int *length) {
//	unsigned char *ucTmp;	//RawData test;
//	*length = i2d_EC_PUBKEY(pkey, NULL);
//	*derPublicKey = (unsigned char *)malloc(*length);
//	ucTmp = *derPublicKey;
//	i2d_EC_PUBKEY(pkey, &ucTmp);
//}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
//EVP_PKEY *to_pkey_rsa_public_key(const unsigned char *derPublicKey, int length) {
//	EVP_PKEY *pkey = EVP_PKEY_new();
//	RSA *rsa;
//
//	BIO *bio = BIO_new(BIO_s_mem());
//    BIO_write(bio, derPublicKey, length);
//    rsa = d2i_RSA_PUBKEY_bio(bio, NULL);
//    BIO_free_all(bio);
//    EVP_PKEY_set1_RSA(pkey,rsa);
//
//	return pkey;
//}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
//EVP_PKEY *to_pkey_rsa_private_key(const unsigned char *derPrivateKey, int length) {
//	EVP_PKEY *pkey = EVP_PKEY_new();
//	RSA *rsa;
//
//	BIO *bio = BIO_new(BIO_s_mem());
//    BIO_write(bio, derPrivateKey, length);
//    rsa = d2i_RSAPrivateKey_bio(bio, NULL);
//    BIO_free_all(bio);
//    EVP_PKEY_set1_RSA(pkey,rsa);
//
//	return pkey;
//}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
EVP_PKEY *to_pkey_ec_public_key(const unsigned char *derPublicKey, int length) {
	EVP_PKEY *pkey = EVP_PKEY_new();
	EC_KEY *ec;

	BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, derPublicKey, length);
    ec = d2i_EC_PUBKEY_bio(bio, NULL);
    BIO_free_all(bio);
    EVP_PKEY_set1_EC_KEY(pkey,ec);

	return pkey;
}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
EVP_PKEY *to_pkey_ec_private_key(const unsigned char *derPrivateKey, int length) {
	EVP_PKEY *pkey = EVP_PKEY_new();
	EC_KEY *ec;

	BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, derPrivateKey, length);
    ec = d2i_ECPrivateKey_bio(bio, NULL);
    BIO_free_all(bio);
    EVP_PKEY_set1_EC_KEY(pkey,ec);

	return pkey;
}

int CryptoService::initialize() {
	int mode, ret, rc;

	// try to initialize using ERR_load_crypto_strings and OpenSSL_add_all_algorithms
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	// turn on FIPS_mode
	mode = FIPS_mode();

	if(mode == 0)
	{
		rc = FIPS_mode_set(1);

		if(rc == 0) {
			return CKM_CRYPTO_INIT_ERROR;
		}

		return CKM_CRYPTO_INIT_ERROR;
	}

	// initialize entropy
	ret = RAND_load_file(DEV_RANDOM_FILE, 32);

	if(ret != 32) {
		return CKM_CRYPTO_INIT_ERROR;
	}

	return CKM_CRYPTO_INIT_SUCCESS;
}

int CryptoService::createKeyPairRSA(const int size, // size in bits [1024, 2048, 4096]
		KeyRSAPrivate &createdPrivateKey,  // returned value
        KeyRSAPublic &createdPublicKey)  // returned value
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	RawBuffer priKey_tmp, pubKey_tmp;
	const std::string null_password;

	EVP_PKEY *pparam = NULL;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_paramgen_init(ctx);
	EVP_PKEY_paramgen(ctx,&pparam);
	EVP_PKEY_CTX_new(pparam, NULL);
	EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    LogDebug("Generating RSA key pair start.");

    if(!ctx) {
		return CKM_CRYPTO_CTX_ERROR;
	}

	if(EVP_PKEY_keygen_init(ctx) <= 0) {
		if(ctx) EVP_PKEY_CTX_free(ctx);
		return CKM_CRYPTO_PKEYINIT_ERROR;
	}

	if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,size) <= 0) {
		if(ctx) EVP_PKEY_CTX_free(ctx);
		return CKM_CRYPTO_PKEYSET_ERROR;
	}

	if(!EVP_PKEY_keygen(ctx, &pkey)) {
		if(ctx) EVP_PKEY_CTX_free(ctx);
		return CKM_CRYPTO_PKEYGEN_ERROR;
	}

    LogDebug("Generating RSA key pair end.");

    // convert to rsa key
	RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);

    createdPrivateKey = KeyRSAPrivate(rsa_key);
    createdPublicKey = KeyRSAPublic(rsa_key);

	if(pkey)
		EVP_PKEY_free(pkey);
	if(ctx)
		EVP_PKEY_CTX_free(ctx);

	return CKM_CRYPTO_CREATEKEY_SUCCESS;
}

int CryptoService::createKeyPairECDSA(ElipticCurve type,
		KeyECDSAPrivate &createdPrivateKey,  // returned value
        KeyECDSAPublic &createdPublicKey)  // returned value
{
		int ecCurve = -1;
		EVP_PKEY_CTX *pctx = NULL;
		EVP_PKEY_CTX *kctx = NULL;
		EVP_PKEY *pkey = NULL;
		EVP_PKEY *pparam = NULL;
		RawBuffer priKey_tmp, pubKey_tmp, null_password;

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
		}

		/* Create the context for generating the parameters */
		if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
			return CKM_CRYPTO_KEYGEN_ERROR;
		}

		if(!EVP_PKEY_paramgen_init(pctx)) {
			if(pctx) EVP_PKEY_CTX_free(pctx);
			return CKM_CRYPTO_KEYGEN_ERROR;
		}

		if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ecCurve)) {
			if(pctx) EVP_PKEY_CTX_free(pctx);
			return CKM_CRYPTO_KEYGEN_ERROR;
		}

		/* Generate parameters */
		if(!EVP_PKEY_paramgen(pctx, &pparam)) {
			if(pparam) EVP_PKEY_free(pparam);
			if(pctx) EVP_PKEY_CTX_free(pctx);
			return CKM_CRYPTO_KEYGEN_ERROR;
		}

		// Start to generate key
		if(pparam != NULL) {
			if(!(kctx = EVP_PKEY_CTX_new(pparam, NULL))) {
				if(pparam) EVP_PKEY_free(pparam);
				if(pctx) EVP_PKEY_CTX_free(pctx);
				return CKM_CRYPTO_KEYGEN_ERROR;
			}
		}
		else {
			/* Create context for key generation */
			if(!(kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
				if(pparam) EVP_PKEY_free(pparam);
				if(pctx) EVP_PKEY_CTX_free(pctx);
				return CKM_CRYPTO_KEYGEN_ERROR;
			}
		}

		if(!EVP_PKEY_keygen_init(kctx)) {
			if(pparam) EVP_PKEY_free(pparam);
			if(pctx) EVP_PKEY_CTX_free(pctx);
			if(kctx) EVP_PKEY_CTX_free(kctx);
		}

		/* Generate the key */
		if(!EVP_PKEY_keygen(kctx, &pkey)) {
			if(pparam) EVP_PKEY_free(pparam);
			if(pctx) EVP_PKEY_CTX_free(pctx);
			if(kctx) EVP_PKEY_CTX_free(kctx);
		}

		// convert to rsa key
		EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);

        createdPrivateKey = KeyECDSAPrivate(ec_key);
        createdPublicKey = KeyECDSAPublic(ec_key);

		if(pkey)
			EVP_PKEY_free(pkey);
		if(pparam)
			EVP_PKEY_free(pparam);
		if(pctx)
			EVP_PKEY_CTX_free(pctx);
		if(kctx)
			EVP_PKEY_CTX_free(kctx);

		return CKM_CRYPTO_CREATEKEY_SUCCESS;
}

int CryptoService::createSignature(const GenericKey &privateKey,
                         const RawBuffer &message,
                         const HashAlgorithm hashAlgo,
                         const RSAPaddingAlgorithm padAlgo,
                         RawBuffer &signature)
{
	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pctx;
	int ret = EVP_FAIL;
	int rsa_padding = -1;
	EVP_PKEY *private_pkey;
	RawBuffer data;
	const EVP_MD *md_algo;

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
		return CKM_CRYPTO_NOT_SUPPORT_ALGO_ERROR;
	}

	if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
		switch(padAlgo) {
		case RSAPaddingAlgorithm::XRSA_PKCS1_PADDING:
			rsa_padding = RSA_PKCS1_PADDING;
			break;
		case RSAPaddingAlgorithm::XRSA_X931_PADDING:
			rsa_padding = RSA_X931_PADDING;
			break;
		default:
			return CKM_CRYPTO_NOT_SUPPORT_ALGO_ERROR;
		}
    } else if (privateKey.getType() != KeyType::KEY_ECDSA_PRIVATE) {
        return CKM_CRYPTO_NOT_SUPPORT_KEY_TYPE;
    }

    private_pkey = privateKey.getEVPKEY();

	// Create the Message Digest Context
	if(!(mdctx = EVP_MD_CTX_create())) {
		return CKM_SIG_GEN_ERROR;
	}
	if(EVP_SUCCESS != EVP_DigestSignInit(mdctx, &pctx, md_algo, NULL, private_pkey)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
        if(private_pkey) EVP_PKEY_free(private_pkey);
		return CKM_SIG_GEN_ERROR;
	}

	/* Set padding algorithm */
	if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
		if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
			if(mdctx) EVP_MD_CTX_destroy(mdctx);
            if(private_pkey) EVP_PKEY_free(private_pkey);
			return CKM_SIG_GEN_ERROR;
		}
	}

	/* Call update with the message */
	char msg[message.size()];
	memcpy(msg, message.data(),message.size());
	if(EVP_SUCCESS != EVP_DigestSignUpdate(mdctx, msg, message.size())) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
        if(private_pkey) EVP_PKEY_free(private_pkey);
		return CKM_SIG_GEN_ERROR;
	}

	/* Finalize the DigestSign operation */
	/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	 * signature. Length is returned in slen */
	size_t slen;
	if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
        if(private_pkey) EVP_PKEY_free(private_pkey);
		return CKM_SIG_GEN_ERROR;
	}
	/* Allocate memory for the signature based on size in slen */
	unsigned char sig[slen];

	/* Obtain the signature */
	if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx, sig, &slen)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
        if(private_pkey) EVP_PKEY_free(private_pkey);
		return CKM_SIG_GEN_ERROR;
	}

	// Set value to return RawData
	signature.assign(sig, sig+slen);

	/* Success */
	ret = EVP_SUCCESS;
	if(mdctx) EVP_MD_CTX_destroy(mdctx);
    if(private_pkey) EVP_PKEY_free(private_pkey);
	return ret;
}

int CryptoService::verifySignature(const GenericKey &publicKey,
                    const RawBuffer &message,
                    const RawBuffer &signature,
                    const HashAlgorithm hashAlgo,
                    const RSAPaddingAlgorithm padAlgo){

	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY_CTX *pctx;
	int ret = EVP_FAIL;
	int rsa_padding = -1;
	const EVP_MD *md_algo;
	EVP_PKEY *public_pkey;
	RawBuffer data;

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
			return CKM_CRYPTO_NOT_SUPPORT_ALGO_ERROR;
	}

	if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
		switch(padAlgo) {
		case RSAPaddingAlgorithm::XRSA_PKCS1_PADDING:
			rsa_padding = RSA_PKCS1_PADDING;
			break;
		case RSAPaddingAlgorithm::XRSA_X931_PADDING:
			rsa_padding = RSA_X931_PADDING;
			break;
		default:
			return CKM_CRYPTO_NOT_SUPPORT_ALGO_ERROR;
		}

	} else if(publicKey.getType() != KeyType::KEY_ECDSA_PUBLIC) {
		return CKM_CRYPTO_NOT_SUPPORT_KEY_TYPE;
	}

    public_pkey = publicKey.getEVPKEY();

    if (NULL == public_pkey)
        return CKM_CRYPTO_PKEYSET_ERROR;

	char msg[message.size()];
	memcpy(msg, message.data(),message.size());

	unsigned char sig[signature.size()];
	memcpy(sig, signature.data(),signature.size());

	/* Create the Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create())) {
        if (public_pkey) EVP_PKEY_free(public_pkey);
		return CKM_SIG_VERIFY_OPER_ERROR;
	}

	if(EVP_SUCCESS != EVP_DigestVerifyInit(mdctx, &pctx, md_algo, NULL, public_pkey)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
        if (public_pkey) EVP_PKEY_free(public_pkey);
		return CKM_SIG_VERIFY_OPER_ERROR;
	}

	if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
		if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding))  {
			if(mdctx) EVP_MD_CTX_destroy(mdctx);
            if (public_pkey) EVP_PKEY_free(public_pkey);
			return CKM_SIG_VERIFY_OPER_ERROR;
		}
	}

	if(EVP_SUCCESS != EVP_DigestVerifyUpdate(mdctx, msg, message.size()) ) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
        if (public_pkey) EVP_PKEY_free(public_pkey);
		return CKM_SIG_VERIFY_OPER_ERROR;
    }

	if(EVP_SUCCESS != EVP_DigestVerifyFinal(mdctx, sig, signature.size()) ) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
        if (public_pkey) EVP_PKEY_free(public_pkey);
		return CKM_SIG_VERIFY_OPER_ERROR;
    }

	ret = EVP_SUCCESS;
	if(mdctx) EVP_MD_CTX_destroy(mdctx);
    if (public_pkey) EVP_PKEY_free(public_pkey);
	return ret;
}


int CryptoService::verifyCertificateChain(const CertificateImpl &certificate,
         const CertificateImplVector &untrustedCertificates,
         const CertificateImplVector &userTrustedCertificates,
         CertificateImplVector &certificateChainVector) {
	X509 *cert = X509_new();
	rawBufferToX509(&cert, certificate.getDER());
	
	std::vector<X509 *> trustedCerts;
	std::vector<X509 *> userTrustedCerts;
	std::vector<X509 *> untrustedChain;

	X509 *tempCert;

	STACK_OF(X509) *sysCerts = loadSystemCerts(CKM_SYSTEM_CERTS_PATH);

	while((tempCert = sk_X509_pop(sysCerts)) != NULL) {
		trustedCerts.push_back(tempCert);
	}
 
	for(unsigned int i=0;i<userTrustedCertificates.size();i++) {
                tempCert = X509_new();
                rawBufferToX509(&tempCert, userTrustedCertificates[i].getDER());
                userTrustedCerts.push_back(tempCert);
        }

	for(unsigned int i=0;i<untrustedCertificates.size();i++) {
		tempCert = X509_new();
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

	X509_free(cert);
	
	for(unsigned int i=0;i<trustedCerts.size();i++) {
		X509_free(trustedCerts[i]);
	}

	for(unsigned int i=0;i<untrustedChain.size();i++) {
		X509_free(untrustedChain[i]);
	}

	for(unsigned int i=0;i<userTrustedCerts.size();i++) {
		X509_free(userTrustedCerts[i]);
	}

	return EVP_SUCCESS;
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
	int errnum;
	const char *errstr;
	if(verified == OPENSSL_SUCCESS) {
		STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
		X509 *cert;
		while((cert = sk_X509_pop(chain))) {
			certChain.insert(certChain.begin(),cert);
		}
	}else {
		errnum = X509_STORE_CTX_get_error(ctx);
		errstr = X509_verify_cert_error_string(errnum);
	}

	X509_STORE_CTX_cleanup(ctx);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(tstore);
	sk_X509_free(uchain);
	ctx = NULL;
	tstore = NULL;
	uchain = NULL;

	if(verified != OPENSSL_SUCCESS) {
		throw std::string(errstr);
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
