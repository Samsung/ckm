#include <iostream>
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
#include <client-key-impl.h>
#include <CryptoService.h>

namespace CKM {

CryptoService::CryptoService(){
}

CryptoService::~CryptoService(){
}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
void to_string_rsa_private_key(RSA *pkey, unsigned char **derPrivateKey, int *length) {
	unsigned char *ucTmp;
	*length = i2d_RSAPrivateKey(pkey, NULL);
	*derPrivateKey = (unsigned char *)malloc(*length);
	ucTmp = *derPrivateKey;
	i2d_RSAPrivateKey(pkey, &ucTmp);
}

void to_string_rsa_public_key(RSA *pkey, unsigned char **derPublicKey, int *length) {
	unsigned char *ucTmp;
	*length = i2d_RSA_PUBKEY(pkey, NULL);
	*derPublicKey = (unsigned char *)malloc(*length);
	ucTmp = *derPublicKey;
	i2d_RSA_PUBKEY(pkey, &ucTmp);
}

void to_string_ec_private_key(EC_KEY *pkey, unsigned char **derPrivateKey, int *length) {
	unsigned char *ucTmp;
	*length = i2d_ECPrivateKey(pkey, NULL);
	*derPrivateKey = (unsigned char *)malloc(*length);
	ucTmp = *derPrivateKey;
	i2d_ECPrivateKey(pkey, &ucTmp);
}

void to_string_ec_public_key(EC_KEY *pkey, unsigned char **derPublicKey, int *length) {
	unsigned char *ucTmp;	//RawData test;
	*length = i2d_EC_PUBKEY(pkey, NULL);
	*derPublicKey = (unsigned char *)malloc(*length);
	ucTmp = *derPublicKey;
	i2d_EC_PUBKEY(pkey, &ucTmp);
}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
EVP_PKEY *to_pkey_rsa_public_key(const unsigned char *derPublicKey, int length) {
	EVP_PKEY *pkey = EVP_PKEY_new();
	RSA *rsa;

	BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, derPublicKey, length);
    rsa = d2i_RSA_PUBKEY_bio(bio, NULL);
    BIO_free_all(bio);
    EVP_PKEY_set1_RSA(pkey,rsa);

	return pkey;
}

// The returned (EVP_PKEY *) should be freed like this [if(pkey) EVP_PKEY_free(pkey);] after use.
EVP_PKEY *to_pkey_rsa_private_key(const unsigned char *derPrivateKey, int length) {
	EVP_PKEY *pkey = EVP_PKEY_new();
	RSA *rsa;

	BIO *bio = BIO_new(BIO_s_mem());
    BIO_write(bio, derPrivateKey, length);
    rsa = d2i_RSAPrivateKey_bio(bio, NULL);
    BIO_free_all(bio);
    EVP_PKEY_set1_RSA(pkey,rsa);

	return pkey;
}

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

int CryptoService::initalize() {
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
		KeyImpl &createdPrivateKey,  // returned value
		KeyImpl &createdPublicKey)  // returned value
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	unsigned char *derPrivateKey = NULL, *derPublicKey = NULL;
	int priKeyLength, pubKeyLength;
	RawBuffer priKey_tmp, pubKey_tmp;
	const std::string null_password;

	EVP_PKEY *pparam = NULL;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_paramgen_init(ctx);
	EVP_PKEY_paramgen(ctx,&pparam);
	EVP_PKEY_CTX_new(pparam, NULL);
	EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

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

	// convert to rsa key
	RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);

	// Extract private and public key
	to_string_rsa_private_key(rsa_key, &derPrivateKey, &priKeyLength);
	to_string_rsa_public_key(rsa_key, &derPublicKey, &pubKeyLength);

	// Key copy to vector structure
	priKey_tmp.assign(derPrivateKey, derPrivateKey+priKeyLength);
	pubKey_tmp.assign(derPublicKey, derPublicKey+pubKeyLength);

	// Create two keys
	KeyImpl privateKey(priKey_tmp, KeyType::KEY_RSA_PRIVATE, null_password);
	KeyImpl Publickey(pubKey_tmp, KeyType::KEY_RSA_PUBLIC, null_password);

	// Two made key copy to reference structure
	createdPrivateKey = privateKey;
	createdPublicKey = Publickey;

	RawBuffer data;
	data = privateKey.getKey();

	if(derPrivateKey)
		free(derPrivateKey);
	if(derPublicKey)
		free(derPublicKey);
	if(pkey)
		EVP_PKEY_free(pkey);
	if(ctx)
		EVP_PKEY_CTX_free(ctx);

	return CKM_CRYPTO_CREATEKEY_SUCCESS;
}

int CryptoService::createKeyPairECDSA(const Key::ECType type,
		KeyImpl &createdPrivateKey,  // returned value
		KeyImpl &createdPublicKey)  // returned value
{
		unsigned char *derPrivateKey = NULL, *derPublicKey = NULL;
		int priKeyLength, pubKeyLength;
		int ecCurve = -1;
		EVP_PKEY_CTX *pctx = NULL;
		EVP_PKEY_CTX *kctx = NULL;
		EVP_PKEY *pkey = NULL;
		EVP_PKEY *pparam = NULL;
		RawBuffer priKey_tmp, pubKey_tmp, null_password;

		switch(type) {
			case Key::ECType::prime192v1: 
				ecCurve = NID_X9_62_prime192v1; 
				break;
			case Key::ECType::prime256v1: 
				ecCurve = NID_X9_62_prime256v1; 
				break;
			case Key::ECType::secp384r1: 
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

		// Extract private and public key
		to_string_ec_private_key(ec_key, &derPrivateKey, &priKeyLength);
		to_string_ec_public_key(ec_key, &derPublicKey, &pubKeyLength);

		// Key copy to vector structure
		priKey_tmp.assign(derPrivateKey, derPrivateKey+priKeyLength);
		pubKey_tmp.assign(derPublicKey, derPublicKey+pubKeyLength);

		// Create two keys

		//Key(const RawBuffer &rawData, KeyType type, const std::string &password = std::string());

		KeyImpl privateKey(priKey_tmp, KeyType::KEY_ECDSA_PRIVATE, NULL);
		KeyImpl Publickey(pubKey_tmp, KeyType::KEY_ECDSA_PUBLIC, NULL);

		// Two made key copy to reference structure
		// To operate this function, client-key-impl should be modified

		createdPrivateKey = privateKey;
		createdPublicKey = Publickey;

		if(derPrivateKey)
			free(derPrivateKey);
		if(derPublicKey)
			free(derPublicKey);
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

int CryptoService::createSignature(const KeyImpl &privateKey,
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

		data = privateKey.getKey();
		unsigned char derPrivateKey[data.size()];
		memcpy(derPrivateKey, data.data(),data.size());
		private_pkey = to_pkey_rsa_private_key(derPrivateKey, data.size());
	} else if(privateKey.getType()==KeyType::KEY_ECDSA_PRIVATE) {
		data = privateKey.getKey();
		unsigned char derPrivateKey[data.size()];
		memcpy(derPrivateKey, data.data(),data.size());
		private_pkey = to_pkey_ec_private_key(derPrivateKey, data.size());
	} else {
		return CKM_CRYPTO_NOT_SUPPORT_KEY_TYPE;
	}

	// Create the Message Digest Context
	if(!(mdctx = EVP_MD_CTX_create())) {
		return CKM_SIG_GEN_ERROR;
	}
	if(EVP_SUCCESS != EVP_DigestSignInit(mdctx, &pctx, md_algo, NULL, private_pkey)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
		return CKM_SIG_GEN_ERROR;
	}

	/* Set padding algorithm */
	if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
		if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
			if(mdctx) EVP_MD_CTX_destroy(mdctx);
			return CKM_SIG_GEN_ERROR;
		}
	}

	/* Call update with the message */
	char msg[message.size()];
	memcpy(msg, message.data(),message.size());
	if(EVP_SUCCESS != EVP_DigestSignUpdate(mdctx, msg, message.size())) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
		return CKM_SIG_GEN_ERROR;
	}

	/* Finalize the DigestSign operation */
	/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	 * signature. Length is returned in slen */
	size_t slen;
	if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
		return CKM_SIG_GEN_ERROR;
	}
	/* Allocate memory for the signature based on size in slen */
	unsigned char sig[slen];

	/* Obtain the signature */
	if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx, sig, &slen)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
		return CKM_SIG_GEN_ERROR;
	}

	// Set value to return RawData
	signature.assign(sig, sig+slen);

	/* Success */
	ret = EVP_SUCCESS;
	if(mdctx) EVP_MD_CTX_destroy(mdctx);
	return ret;
}

int CryptoService::verifySignature(const KeyImpl &publicKey,
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

		data = publicKey.getKey();
		unsigned char derPublicKey[data.size()];
		memcpy(derPublicKey, data.data(),data.size());
		public_pkey = to_pkey_rsa_public_key(derPublicKey, data.size());
	} else if(publicKey.getType()==KeyType::KEY_ECDSA_PUBLIC) {
		data = publicKey.getKey();
		unsigned char derPublicKey[data.size()];
		memcpy(derPublicKey, data.data(),data.size());
		public_pkey = to_pkey_ec_public_key(derPublicKey, data.size());
	} else {
		return CKM_CRYPTO_NOT_SUPPORT_KEY_TYPE;
	}

	char msg[message.size()];
	memcpy(msg, message.data(),message.size());

	unsigned char sig[signature.size()];
	memcpy(sig, signature.data(),signature.size());

	/* Create the Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create())) {
		return CKM_SIG_VERIFY_OPER_ERROR;
	}

	if(EVP_SUCCESS != EVP_DigestVerifyInit(mdctx, &pctx, md_algo, NULL, public_pkey)) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
		return CKM_SIG_VERIFY_OPER_ERROR;
	}

	if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
		if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding))  {
			if(mdctx) EVP_MD_CTX_destroy(mdctx);
			return CKM_SIG_VERIFY_OPER_ERROR;
		}
	}

	if(EVP_SUCCESS != EVP_DigestVerifyUpdate(mdctx, msg, message.size()) ) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
		return CKM_SIG_VERIFY_OPER_ERROR;
    }

	if(EVP_SUCCESS != EVP_DigestVerifyFinal(mdctx, sig, signature.size()) ) {
		if(mdctx) EVP_MD_CTX_destroy(mdctx);
		return CKM_SIG_VERIFY_OPER_ERROR;
    }

	ret = EVP_SUCCESS;
	if(mdctx) EVP_MD_CTX_destroy(mdctx);
	return ret;
}

//int CryptoService::verifyCertificateChain(const CertificateImpl &certificate,
//         const CertificateImplVector &untrustedCertificates,
//         const CertificateImplVector &userTrustedCertificates,
//         CertificateImplVector &certificateChainVector) {
//
//	return -1;
//}
}
