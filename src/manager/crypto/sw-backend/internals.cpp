/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file       internals.cpp
 * @author
 * @version    1.0
 */
#include <exception>
#include <fstream>
#include <utility>

#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/obj_mac.h>

#include <ckm/ckm-error.h>
#include <assert.h>
#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <sw-backend/internals.h>

#define OPENSSL_SUCCESS 1       // DO NOTCHANGE THIS VALUE
#define OPENSSL_FAIL    0       // DO NOTCHANGE THIS VALUE
#define DEV_HW_RANDOM_FILE    "/dev/hwrng"
#define DEV_URANDOM_FILE    "/dev/urandom"

namespace {
typedef std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> EvpMdCtxUPtr;
typedef std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> EvpPkeyCtxUPtr;
typedef std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> EvpPkeyUPtr;

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;
typedef int(*I2D_CONV)(BIO*, EVP_PKEY*);
CKM::RawBuffer i2d(I2D_CONV fun, EVP_PKEY* pkey) {
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (NULL == pkey) {
        LogDebug("attempt to parse an empty key!");
        ThrowMsg(CKM::Crypto::Exception::InternalError, "attempt to parse an empty key!");
    }

    if (NULL == bio.get()) {
        LogError("Error in memory allocation! Function: BIO_new.");
        ThrowMsg(CKM::Crypto::Exception::InternalError, "Error in memory allocation! Function: BIO_new.");
    }

    if (1 != fun(bio.get(), pkey)) {
        LogError("Error in conversion EVP_PKEY to DER");
        ThrowMsg(CKM::Crypto::Exception::InternalError, "Error in conversion EVP_PKEY to DER");
    }

    CKM::RawBuffer output(8196);

    int size = BIO_read(bio.get(), output.data(), output.size());

    if (size <= 0) {
        LogError("Error in BIO_read: " << size);
        ThrowMsg(CKM::Crypto::Exception::InternalError, "Error in BIO_read: " << size);
    }

    output.resize(size);
    return output;
}
} // anonymous namespace

namespace CKM {
namespace Crypto {
namespace SW {
namespace Internals {

int initialize() {
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
            ThrowMsg(Crypto::Exception::InternalError, "Error in U_RAND_file_load");
        }
    }

    return CKM_CRYPTO_INIT_SUCCESS;
}

const EVP_MD *getMdAlgo(const HashAlgorithm hashAlgo) {
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
        ThrowMsg(Crypto::Exception::InternalError, "Error in hashAlgorithm value");
    }
    return md_algo;
}

int getRsaPadding(const RSAPaddingAlgorithm padAlgo) {
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
        ThrowMsg(Crypto::Exception::InternalError, "Error in RSAPaddingAlgorithm value");
    }
    return rsa_padding;
}

TokenPair createKeyPairRSA(CryptoBackend backendId, const int size)
{
    EvpPkeyUPtr pkey;

    // check the parameters of functions
    if(size!=1024 && size!=2048 && size!=4096) {
        LogError("Error in RSA input size");
        ThrowMsg(Crypto::Exception::InputParam, "Error in RSA input size");
    }

    EvpPkeyCtxUPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), EVP_PKEY_CTX_free);
    if(!ctx) {
        LogError("Error in EVP_PKEY_CTX_new_id function !!");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_new_id function !!");
    }

    if(EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        LogError("Error in EVP_PKEY_keygen_init function !!");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_keygen_init function !!");
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), size) <= 0) {
        LogError("Error in EVP_PKEY_CTX_set_rsa_keygen_bits function !!");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_set_rsa_keygen_bits function !!");
    }

    EVP_PKEY *pkeyTmp = NULL;
    if(!EVP_PKEY_keygen(ctx.get(), &pkeyTmp)) {
        LogError("Error in EVP_PKEY_keygen function !!");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_keygen function !!");
    }
    pkey = EvpPkeyUPtr(pkeyTmp, EVP_PKEY_free);

    return std::make_pair<Token, Token>(Token(backendId, DataType(KeyType::KEY_RSA_PRIVATE), i2d(i2d_PrivateKey_bio, pkey.get())),
                                        Token(backendId, DataType(KeyType::KEY_RSA_PUBLIC), i2d(i2d_PUBKEY_bio, pkey.get())));
}


TokenPair createKeyPairDSA(CryptoBackend backendId, const int size)
{
    EvpPkeyUPtr pkey;
    EvpPkeyUPtr pparam;

    // check the parameters of functions
    if(size!=1024 && size!=2048 && size!=3072 && size!=4096) {
        LogError("Error in DSA input size");
        ThrowMsg(Exception::InputParam, "Error in DSA input size");
    }

    /* Create the context for generating the parameters */
    EvpPkeyCtxUPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL), EVP_PKEY_CTX_free);
    if(!pctx) {
        LogError("Error in EVP_PKEY_CTX_new_id function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_new_id function");
    }

    if(EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx.get())) {
        LogError("Error in EVP_PKEY_paramgen_init function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_paramgen_init function");
    }

    if(EVP_SUCCESS != EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx.get(), size)) {
        LogError("Error in EVP_PKEY_CTX_set_dsa_paramgen_bits(" << size << ") function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_set_dsa_paramgen_bits(" << size << ") function");
    }

    /* Generate parameters */
    EVP_PKEY *pparamTmp = NULL;
    if(EVP_SUCCESS != EVP_PKEY_paramgen(pctx.get(), &pparamTmp)) {
        LogError("Error in EVP_PKEY_paramgen function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_paramgen function");
    }
    pparam = EvpPkeyUPtr(pparamTmp, EVP_PKEY_free);

    // Start to generate key
    EvpPkeyCtxUPtr kctx(EVP_PKEY_CTX_new(pparam.get(), NULL), EVP_PKEY_CTX_free);
    if(!kctx) {
        LogError("Error in EVP_PKEY_CTX_new function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_SUCCESS != EVP_PKEY_keygen_init(kctx.get())) {
        LogError("Error in EVP_PKEY_keygen_init function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_keygen_init function");
    }

    /* Generate the key */
    EVP_PKEY *pkeyTmp = NULL;
    if(!EVP_PKEY_keygen(kctx.get(), &pkeyTmp)) {
        LogError("Error in EVP_PKEY_keygen function !!");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_keygen function !!");
    }
    pkey = EvpPkeyUPtr(pkeyTmp, EVP_PKEY_free);

    return std::make_pair<Token, Token>(Token(backendId, DataType(KeyType::KEY_DSA_PRIVATE), i2d(i2d_PrivateKey_bio, pkey.get())),
                                        Token(backendId, DataType(KeyType::KEY_DSA_PUBLIC), i2d(i2d_PUBKEY_bio, pkey.get())));
}

TokenPair createKeyPairECDSA(CryptoBackend backendId, ElipticCurve type)
{
    int ecCurve = NOT_DEFINED;
    EvpPkeyUPtr pkey;
    EvpPkeyUPtr pparam;

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
        ThrowMsg(Exception::InputParam, "Error in EC type");
    }

    /* Create the context for generating the parameters */
    EvpPkeyCtxUPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free);
    if(!pctx) {
        LogError("Error in EVP_PKEY_CTX_new_id function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_new_id function");
    }

    if(EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx.get())) {
        LogError("Error in EVP_PKEY_paramgen_init function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_paramgen_init function");
    }

    if(EVP_SUCCESS != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), ecCurve)) {
        LogError("Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid function");
    }

    /* Generate parameters */
    EVP_PKEY *pparamTmp = NULL;
    if(EVP_SUCCESS != EVP_PKEY_paramgen(pctx.get(), &pparamTmp)) {
        LogError("Error in EVP_PKEY_paramgen function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_paramgen function");
    }
    pparam = EvpPkeyUPtr(pparamTmp, EVP_PKEY_free);

    // Start to generate key
    EvpPkeyCtxUPtr kctx(EVP_PKEY_CTX_new(pparam.get(), NULL), EVP_PKEY_CTX_free);
    if(!kctx) {
        LogError("Error in EVP_PKEY_CTX_new function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_SUCCESS != EVP_PKEY_keygen_init(kctx.get())) {
        LogError("Error in EVP_PKEY_keygen_init function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_keygen_init function");
    }

    /* Generate the key */
    EVP_PKEY *pkeyTmp = NULL;
    if(!EVP_PKEY_keygen(kctx.get(), &pkeyTmp)) {
        LogError("Error in EVP_PKEY_keygen function !!");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_keygen function !!");
        }
        pkey = EvpPkeyUPtr(pkeyTmp, EVP_PKEY_free);

    return std::make_pair<Token, Token>(Token(backendId, DataType(KeyType::KEY_ECDSA_PRIVATE), i2d(i2d_PrivateKey_bio, pkey.get())),
                                        Token(backendId, DataType(KeyType::KEY_ECDSA_PUBLIC), i2d(i2d_PUBKEY_bio, pkey.get())));
}

RawBuffer sign(EVP_PKEY *pkey,
    const CryptoAlgorithm &alg,
    const RawBuffer &message)
{
    int rsa_padding = NOT_DEFINED;
    const EVP_MD *md_algo = NULL;

    HashAlgorithm hashTmp = HashAlgorithm::NONE;
    alg.getParam(ParamName::SV_HASH_ALGO, hashTmp);
    md_algo = getMdAlgo(hashTmp);

    RSAPaddingAlgorithm rsaPad = RSAPaddingAlgorithm::NONE;
    alg.getParam(ParamName::SV_RSA_PADDING, rsaPad);
    rsa_padding = getRsaPadding(rsaPad);

//
//    if((privateKey.getType() != KeyType::KEY_RSA_PRIVATE) &&
//       (privateKey.getType() != KeyType::KEY_DSA_PRIVATE) &&
//       (privateKey.getType() != KeyType::KEY_ECDSA_PRIVATE))
//    {
//        LogError("Error in private key type");
//        ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in private key type");
//    }
//
//    if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
//        rsa_padding = getRsaPadding(padAlgo);
//    }

    if (NULL == pkey) {
        LogError("Error in EVP_PKEY_keygen function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_keygen function");
    }

    if(md_algo == NULL) {
        return signMessage(pkey, message, rsa_padding);
    }

    return digestSignMessage(pkey,message, md_algo, rsa_padding);
}

RawBuffer signMessage(EVP_PKEY *privKey,
        const RawBuffer &message,
        const int rsa_padding)
{
    EvpPkeyCtxUPtr pctx(EVP_PKEY_CTX_new(privKey, NULL), EVP_PKEY_CTX_free);
 
    if(!pctx.get()) {
        LogError("Error in EVP_PKEY_CTX_new function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_PKEY_sign_init(pctx.get()) != EVP_SUCCESS) {
        LogError("Error in EVP_PKEY_sign_init function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_sign_init function");
    }

    /* Set padding algorithm */
    if(EVP_PKEY_type(privKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx.get(), rsa_padding)) {
            LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
            ThrowMsg(Crypto::Exception::InternalError,
                     "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    /* Finalize the Sign operation */
    /* First call EVP_PKEY_sign with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    size_t slen;
    if(EVP_SUCCESS != EVP_PKEY_sign(pctx.get(), NULL, &slen, message.data(), message.size())) {
        LogError("Error in EVP_PKEY_sign function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_sign function");
    }

    /* Allocate memory for the signature based on size in slen */
    RawBuffer sig(slen);

    if(EVP_SUCCESS == EVP_PKEY_sign(pctx.get(),
                                    sig.data(),
                                    &slen,
                                    message.data(),
                                    message.size()))
    {
        // Set value to return RawData
        sig.resize(slen);
        return sig;
    }

    LogError("Error in EVP_PKEY_sign function. Input param error.");
    ThrowMsg(Crypto::Exception::InputParam, "Error in EVP_PKEY_sign function. Input param error.");
}

RawBuffer digestSignMessage(EVP_PKEY *privKey,
        const RawBuffer &message,
        const EVP_MD *md_algo,
        const int rsa_padding)
{
    EvpMdCtxUPtr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
 
    EVP_PKEY_CTX *pctx = NULL;

    // Create the Message Digest Context
    if(!mdctx.get()) {
        LogError("Error in EVP_MD_CTX_create function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_MD_CTX_create function");
    }

    if(EVP_SUCCESS != EVP_DigestSignInit(mdctx.get(), &pctx, md_algo, NULL, privKey)) {
        LogError("Error in EVP_DigestSignInit function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_DigestSignInit function");
    }

    /* Set padding algorithm */
    if(EVP_PKEY_type(privKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
            ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    /* Call update with the message */
    if(EVP_SUCCESS != EVP_DigestSignUpdate(mdctx.get(), message.data(), message.size())) {
        LogError("Error in EVP_DigestSignUpdate function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_DigestSignUpdate function");
    }

    /* Finalize the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    size_t slen;
    if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx.get(), NULL, &slen)) {
        LogError("Error in EVP_DigestSignFinal function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_DigestSignFinal function");
    }

    /* Allocate memory for the signature based on size in slen */
    RawBuffer sig(slen);

    /* Obtain the signature */
    if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx.get(), sig.data(), &slen)) {
        LogError("Error in EVP_DigestSignFinal function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_DigestSignFinal function");
    }

    // Set value to return RawData
    sig.resize(slen);
    return sig;
}

int verify(EVP_PKEY *pkey,
    const CryptoAlgorithm &alg,
    const RawBuffer &message,
    const RawBuffer &signature)
{
    int rsa_padding = NOT_DEFINED;
    const EVP_MD *md_algo = NULL;

    HashAlgorithm hashTmp = HashAlgorithm::NONE;
    alg.getParam(ParamName::SV_HASH_ALGO, hashTmp);
    md_algo = getMdAlgo(hashTmp);

    RSAPaddingAlgorithm rsaPad = RSAPaddingAlgorithm::NONE;
    alg.getParam(ParamName::SV_RSA_PADDING, rsaPad);
    rsa_padding = getRsaPadding(rsaPad);

//
//    if((publicKey.getType() != KeyType::KEY_RSA_PUBLIC) &&
//       (publicKey.getType() != KeyType::KEY_DSA_PUBLIC) &&
//       (publicKey.getType() != KeyType::KEY_ECDSA_PUBLIC))
//    {
//        LogError("Error in private key type");
//        ThrowMsg(CryptoService::Exception::Crypto_internal, "Error in private key type");
//    }
//
//    if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
//        rsa_padding = getRsaPadding(padAlgo);
//    }

//    auto shrPKey = publicKey.getEvpShPtr();
    if (NULL == pkey) {
        LogError("Error in getEvpShPtr function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in getEvpShPtr function");
    }

    if (md_algo == NULL) {
        return verifyMessage(pkey, message, signature, rsa_padding);
    }

    return digestVerifyMessage(pkey, message, signature, md_algo, rsa_padding);
}

int verifyMessage(EVP_PKEY *pubKey,
        const RawBuffer &message,
        const RawBuffer &signature,
        const int rsa_padding)
{
    EvpPkeyCtxUPtr pctx(EVP_PKEY_CTX_new(pubKey, NULL), EVP_PKEY_CTX_free);

    if(!pctx.get()) {
        LogError("Error in EVP_PKEY_CTX_new function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_PKEY_verify_init(pctx.get()) != EVP_SUCCESS) {
        LogError("Error in EVP_PKEY_verify_init function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_verify_init function");
    }

    /* Set padding algorithm  */
    if(EVP_PKEY_type(pubKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx.get(), rsa_padding)) {
            LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
            ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    if(EVP_SUCCESS == EVP_PKEY_verify(pctx.get(), signature.data(), signature.size(), message.data(), message.size())) {
        return CKM_API_SUCCESS;
    } 

    LogError("EVP_PKEY_verify Failed");
    return CKM_API_ERROR_VERIFICATION_FAILED;
}

int digestVerifyMessage(EVP_PKEY *pubKey,
        const RawBuffer &message,
        const RawBuffer &signature,
        const EVP_MD *md_algo,
        const int rsa_padding)
{
    EvpMdCtxUPtr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
    EVP_PKEY_CTX *pctx = NULL;

    /* Create the Message Digest Context */
    if(!mdctx.get()) {
        LogError("Error in EVP_MD_CTX_create function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_MD_CTX_create function");
    }

    if(EVP_SUCCESS != EVP_DigestVerifyInit(mdctx.get(), &pctx, md_algo, NULL, pubKey)) {
        LogError("Error in EVP_DigestVerifyInit function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_DigestVerifyInit function");
    }

    if(EVP_PKEY_type(pubKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            LogError("Error in EVP_PKEY_CTX_set_rsa_padding function");
            ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    if(EVP_SUCCESS != EVP_DigestVerifyUpdate(mdctx.get(), message.data(), message.size()) ) {
        LogError("Error in EVP_DigestVerifyUpdate function");
        ThrowMsg(Crypto::Exception::InternalError, "Error in EVP_DigestVerifyUpdate function");
    }

    if(EVP_SUCCESS == EVP_DigestVerifyFinal(mdctx.get(), const_cast<unsigned char*>(signature.data()), signature.size()) ) {
        return CKM_API_SUCCESS;
    }

    LogError("EVP_PKEY_verify Failed");
    return CKM_API_ERROR_VERIFICATION_FAILED;
}

} // namespace Internals
} // namespace SW
} // namespace Crypto
} // namespace CKM
