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
#include <key-impl.h>
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
    int hw_rand_ret = 0;
    int u_rand_ret = 0;

    // try to initialize using ERR_load_crypto_strings and OpenSSL_add_all_algorithms
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

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

const EVP_MD *CryptoService::getMdAlgo(const HashAlgorithm hashAlgo) {
    const EVP_MD *md_algo=NULL;
    switch(hashAlgo) {
    case HashAlgorithm::NONE:
        md_algo = NULL;
        break;
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
    return md_algo;
}

int CryptoService::getRsaPadding(const RSAPaddingAlgorithm padAlgo) {
    int rsa_padding = -1;
    switch(padAlgo) {
    case RSAPaddingAlgorithm::NONE:
        rsa_padding = RSA_NO_PADDING;
        break;
    case RSAPaddingAlgorithm::PKCS1:
        rsa_padding = RSA_PKCS1_PADDING;
        break;
    case RSAPaddingAlgorithm::X931:
        rsa_padding = RSA_X931_PADDING;
        break;
    default:
        LogError("Error in RSAPaddingAlgorithm value");
        ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in RSAPaddingAlgorithm value");
    }
    return rsa_padding;
}

int CryptoService::createKeyPairRSA(const int size, // size in bits [1024, 2048, 4096]
        KeyImpl &createdPrivateKey,  // returned value
        KeyImpl &createdPublicKey)  // returned value
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

    KeyImpl::EvpShPtr ptr(pkey, EVP_PKEY_free); // shared ptr will free pkey

    createdPrivateKey = KeyImpl(ptr, KeyType::KEY_RSA_PRIVATE);
    createdPublicKey = KeyImpl(ptr, KeyType::KEY_RSA_PUBLIC);

    if(pparam) {
        EVP_PKEY_free(pparam);
    }

    if(ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return CKM_CRYPTO_CREATEKEY_SUCCESS;
}


int CryptoService::createKeyPairDSA(const int size, // size in bits [1024, 2048, 3072, 4096]
		KeyImpl &createdPrivateKey,  // returned value
		KeyImpl &createdPublicKey)  // returned value
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pparam = NULL;

	// check the parameters of functions
	if(size != 1024 && size !=2048 && size !=3072 && size != 4096) {
		LogError("Error in DSA input size");
		ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in DSA input size");
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
		if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL))) {
			LogError("Error in EVP_PKEY_CTX_new_id function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_new_id function");
		}

		if(EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx)) {
			LogError("Error in EVP_PKEY_paramgen_init function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_paramgen_init function");
		}

		if(EVP_SUCCESS != EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, size)) {
			LogError("Error in EVP_PKEY_CTX_set_dsa_paramgen_bits(" << size << ") function");
			ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_dsa_paramgen_bits(" << size << ") function");
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
	}
	Catch(CryptoService::Exception::opensslError)
	{
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

	KeyImpl::EvpShPtr ptr(pkey, EVP_PKEY_free); // shared ptr will free pkey

	createdPrivateKey = KeyImpl(ptr, KeyType::KEY_DSA_PRIVATE);
	createdPublicKey = KeyImpl(ptr, KeyType::KEY_DSA_PUBLIC);

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


int CryptoService::createKeyPairECDSA(ElipticCurve type,
        KeyImpl &createdPrivateKey,  // returned value
        KeyImpl &createdPublicKey)  // returned value
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

    KeyImpl::EvpShPtr ptr(pkey, EVP_PKEY_free); // shared ptr will free pkey

    createdPrivateKey = KeyImpl(ptr, KeyType::KEY_ECDSA_PRIVATE);
    createdPublicKey = KeyImpl(ptr, KeyType::KEY_ECDSA_PUBLIC);

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

int CryptoService::createSignature(const KeyImpl &privateKey,
        const RawBuffer &message,
        const HashAlgorithm hashAlgo,
        const RSAPaddingAlgorithm padAlgo,
        RawBuffer &signature)
{
    int retCode = CKM_API_SUCCESS;
    int rsa_padding = NOT_DEFINED;
    const EVP_MD *md_algo = NULL;

    md_algo = getMdAlgo(hashAlgo);


    if((privateKey.getType() != KeyType::KEY_RSA_PRIVATE) &&
       (privateKey.getType() != KeyType::KEY_DSA_PRIVATE) &&
       (privateKey.getType() != KeyType::KEY_ECDSA_PRIVATE))
    {
        LogError("Error in private key type");
        ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in private key type");
    }

    if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
        rsa_padding = getRsaPadding(padAlgo);
    }

    auto shrPKey = privateKey.getEvpShPtr();
    if (NULL == shrPKey.get()) {
        LogError("Error in EVP_PKEY_keygen function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_keygen function");
    }

    if(md_algo == NULL) {
        retCode = signMessage(shrPKey.get(), message, rsa_padding, signature);
    }else {
        retCode = digestSignMessage(shrPKey.get(),message, md_algo, rsa_padding, signature);
    }

    return retCode;
}

int CryptoService::signMessage(EVP_PKEY *privKey,
        const RawBuffer &message,
        const int rsa_padding,
        RawBuffer &signature)
{
    int retCode = CKM_API_SUCCESS;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        if(!(pctx = EVP_PKEY_CTX_new(privKey, NULL))) {
            LogError("Error in EVP_PKEY_CTX_new function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_new function");
        }

        if(EVP_PKEY_sign_init(pctx) != EVP_SUCCESS) {
            LogError("Error in EVP_PKEY_sign_init function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_sign_init function");
        }

        /* Set padding algorithm */
        if(EVP_PKEY_type(privKey->type) == EVP_PKEY_RSA) {
            if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
                LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
                ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
            }
        }

        /* Finalize the Sign operation */
        /* First call EVP_PKEY_sign with a NULL sig parameter to obtain the length of the
         * signature. Length is returned in slen */
        size_t slen;
        if(EVP_SUCCESS != EVP_PKEY_sign(pctx, NULL, &slen, message.data(), message.size())) {
            LogError("Error in EVP_PKEY_sign function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_sign function");
        }

        /* Allocate memory for the signature based on size in slen */
        unsigned char sig[slen];

        if(EVP_SUCCESS == EVP_PKEY_sign(pctx, sig, &slen, message.data(), message.size())) {
            // Set value to return RawData
            signature.assign(sig, sig+slen);
            retCode = CKM_API_SUCCESS;
        }else {
            LogError("Error in EVP_PKEY_sign function: check input parameter");
            retCode = CKM_API_ERROR_INPUT_PARAM;
        }
    } Catch(CryptoService::Exception::opensslError) {
        if(pctx != NULL) {
            EVP_PKEY_CTX_free(pctx);
        }
        ReThrowMsg(CryptoService::Exception::opensslError,"Error in openssl function !!");
    }

    if(pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return retCode;
}

int CryptoService::digestSignMessage(EVP_PKEY *privKey,
        const RawBuffer &message,
        const EVP_MD *md_algo,
        const int rsa_padding,
        RawBuffer &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        // Create the Message Digest Context
        if(!(mdctx = EVP_MD_CTX_create())) {
            LogError("Error in EVP_MD_CTX_create function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_MD_CTX_create function");
        }

        if(EVP_SUCCESS != EVP_DigestSignInit(mdctx, &pctx, md_algo, NULL, privKey)) {
            LogError("Error in EVP_DigestSignInit function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestSignInit function");
        }

        /* Set padding algorithm */
        if(EVP_PKEY_type(privKey->type) == EVP_PKEY_RSA) {
            if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
                LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
                ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
            }
        }

        /* Call update with the message */
        if(EVP_SUCCESS != EVP_DigestSignUpdate(mdctx, message.data(), message.size())) {
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

    return CKM_API_SUCCESS;
}

int CryptoService::verifySignature(const KeyImpl &publicKey,
        const RawBuffer &message,
        const RawBuffer &signature,
        const HashAlgorithm hashAlgo,
        const RSAPaddingAlgorithm padAlgo)
{
    int rsa_padding = NOT_DEFINED;
    const EVP_MD *md_algo;
    int retCode = CKM_API_ERROR_VERIFICATION_FAILED;

    md_algo = getMdAlgo(hashAlgo);


    if((publicKey.getType() != KeyType::KEY_RSA_PUBLIC) &&
       (publicKey.getType() != KeyType::KEY_DSA_PUBLIC) &&
       (publicKey.getType() != KeyType::KEY_ECDSA_PUBLIC))
    {
        LogError("Error in private key type");
        ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in private key type");
    }

    if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
        rsa_padding = getRsaPadding(padAlgo);
    }

    auto shrPKey = publicKey.getEvpShPtr();
    if (NULL == shrPKey.get()) {
        LogError("Error in getEvpShPtr function");
        ThrowMsg(CryptoService::Exception::opensslError, "Error in getEvpShPtr function");
    }

    if(md_algo == NULL) {
        retCode = verifyMessage(shrPKey.get(), message, signature, rsa_padding);
    }else {
        retCode = digestVerifyMessage(shrPKey.get(),message, signature, md_algo, rsa_padding);
    }

    return retCode;
}

int CryptoService::verifyMessage(EVP_PKEY *pubKey,
        const RawBuffer &message,
        const RawBuffer &signature,
        const int rsa_padding)
{
    int ret = CKM_API_ERROR_VERIFICATION_FAILED;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        if(!(pctx = EVP_PKEY_CTX_new(pubKey, NULL))) {
            LogError("Error in EVP_PKEY_CTX_new function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_new function");
        }

        if(EVP_PKEY_verify_init(pctx) != EVP_SUCCESS) {
            LogError("Error in EVP_PKEY_verify_init function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_verify_init function");
        }

        /* Set padding algorithm  */
        if(EVP_PKEY_type(pubKey->type) == EVP_PKEY_RSA) {
            if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
                LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
                ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
            }
        }

        if(EVP_SUCCESS == EVP_PKEY_verify(pctx, signature.data(), signature.size(), message.data(), message.size())) {
            ret = CKM_API_SUCCESS;
        }else {
            LogError("EVP_PKEY_verify Failed");
            ret = CKM_API_ERROR_VERIFICATION_FAILED;
        }
    } Catch(CryptoService::Exception::opensslError) {
        if(pctx != NULL) {
            EVP_PKEY_CTX_free(pctx);
        }
        ReThrowMsg(CryptoService::Exception::opensslError,"Error in openssl function !!");
    }

    if(pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }

    return ret;
}

int CryptoService::digestVerifyMessage(EVP_PKEY *pubKey,
        const RawBuffer &message,
        const RawBuffer &signature,
        const EVP_MD *md_algo,
        const int rsa_padding)
{
    int ret = CKM_API_ERROR_VERIFICATION_FAILED;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    Try {
        /* Create the Message Digest Context */
        if(!(mdctx = EVP_MD_CTX_create())) {
            LogError("Error in EVP_MD_CTX_create function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_MD_CTX_create function");
        }

        if(EVP_SUCCESS != EVP_DigestVerifyInit(mdctx, &pctx, md_algo, NULL, pubKey)) {
            LogError("Error in EVP_DigestVerifyInit function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestVerifyInit function");
        }

        if(EVP_PKEY_type(pubKey->type) == EVP_PKEY_RSA) {
            if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
                LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
                ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
            }
        }

        if(EVP_SUCCESS != EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()) ) {
            LogError("Error in EVP_DigestVerifyUpdate function");
            ThrowMsg(CryptoService::Exception::opensslError, "Error in EVP_DigestVerifyUpdate function");
        }

        if(EVP_SUCCESS == EVP_DigestVerifyFinal(mdctx, const_cast<unsigned char*>(signature.data()), signature.size()) ) {
            ret = CKM_API_SUCCESS;
        }else {
            LogError("EVP_PKEY_verify Failed");
            ret = CKM_API_ERROR_VERIFICATION_FAILED;
        }
    } Catch(CryptoService::Exception::opensslError) {
        if(mdctx != NULL) {
            EVP_MD_CTX_destroy(mdctx);
        }
        ReThrowMsg(CryptoService::Exception::opensslError,"Error in openssl function !!");
    }

    if(mdctx != NULL) {
        EVP_MD_CTX_destroy(mdctx);
    }

    return ret;
}
}
