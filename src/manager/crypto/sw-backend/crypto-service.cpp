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
#include <sw-backend/crypto-service.h>
#include <assert.h>
#include <dpl/log/log.h>

#define OPENSSL_SUCCESS 1       // DO NOTCHANGE THIS VALUE
#define OPENSSL_FAIL    0       // DO NOTCHANGE THIS VALUE

namespace CKM {
namespace Crypto {
namespace SW {

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

} // namespace SW
} // namespace Crypto
} // namespace CKM
