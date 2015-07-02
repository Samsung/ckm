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
#include <utility>
#include <algorithm>

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
#include <generic-backend/algo-validation.h>
#include <sw-backend/internals.h>
#include <sw-backend/crypto.h>

#define OPENSSL_SUCCESS 1       // DO NOTCHANGE THIS VALUE
#define OPENSSL_FAIL    0       // DO NOTCHANGE THIS VALUE

namespace CKM {
namespace Crypto {
namespace SW {
namespace Internals {

namespace {
typedef std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> EvpMdCtxUPtr;
typedef std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> EvpPkeyCtxUPtr;
typedef std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> EvpPkeyUPtr;

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;
typedef int(*I2D_CONV)(BIO*, EVP_PKEY*);

const size_t DEFAULT_AES_GCM_TAG_LEN = 128; // tag length in bits according to W3C Crypto API
const size_t DEFAULT_AES_IV_LEN = 16; // default iv size in bytes for AES

RawBuffer i2d(I2D_CONV fun, EVP_PKEY* pkey) {
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (NULL == pkey) {
        ThrowErr(Exc::Crypto::InternalError, "attempt to parse an empty key!");
    }

    if (NULL == bio.get()) {
        ThrowErr(Exc::Crypto::InternalError, "Error in memory allocation! Function: BIO_new.");
    }

    if (1 != fun(bio.get(), pkey)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in conversion EVP_PKEY to DER");
    }

    RawBuffer output(8196);

    int size = BIO_read(bio.get(), output.data(), output.size());

    if (size <= 0) {
        ThrowErr(Exc::Crypto::InternalError, "Error in BIO_read: ", size);
    }

    output.resize(size);
    return output;
}

// encryption / decryption
typedef ParamCheck<ParamName::ALGO_TYPE,
                   AlgoType,
                   true,
                   Type<AlgoType>::Equals<AlgoType::AES_CTR,
                                          AlgoType::AES_CBC,
                                          AlgoType::AES_GCM,
                                          AlgoType::AES_CFB,
                                          AlgoType::RSA_OAEP>> IsEncryption;

typedef ParamCheck<ParamName::ED_IV,
                   RawBuffer,
                   true,
                   Type<size_t>::Equals<DEFAULT_AES_IV_LEN>,
                   BufferSizeGetter> IvSizeCheck;

typedef ParamCheck<ParamName::ED_CTR_LEN,
                   int,
                   false,
                   Type<int>::Equals<128>> CtrLenCheck;

typedef ParamCheck<ParamName::ED_IV,
                   RawBuffer,
                   true,
                   DefaultValidator<size_t>,
                   BufferSizeGetter> GcmIvCheck;

typedef ParamCheck<ParamName::ED_TAG_LEN,
                   int,
                   false,
                   Type<int>::Equals<32, 64, 96, 104, 112, 120, 128>> GcmTagCheck;

// sign / verify
typedef ParamCheck<ParamName::ALGO_TYPE,
                   AlgoType,
                   false,
                   Type<AlgoType>::Equals<AlgoType::RSA_SV,
                                          AlgoType::DSA_SV,
                                          AlgoType::ECDSA_SV>> IsSignVerify;

typedef ParamCheck<ParamName::SV_HASH_ALGO,
                   HashAlgorithm,
                   false,
                   Type<HashAlgorithm>::Equals<HashAlgorithm::NONE,
                                               HashAlgorithm::SHA1,
                                               HashAlgorithm::SHA256,
                                               HashAlgorithm::SHA384,
                                               HashAlgorithm::SHA512>> HashAlgoCheck;

typedef ParamCheck<ParamName::SV_RSA_PADDING,
                   RSAPaddingAlgorithm,
                   false,
                   Type<RSAPaddingAlgorithm>::Equals<RSAPaddingAlgorithm::NONE,
                                                     RSAPaddingAlgorithm::PKCS1,
                                                     RSAPaddingAlgorithm::X931>> RsaPaddingCheck;

// key generation
typedef ParamCheck<ParamName::ALGO_TYPE,
                   AlgoType,
                   true,
                   Type<AlgoType>::Equals<AlgoType::RSA_GEN,
                                          AlgoType::DSA_GEN,
                                          AlgoType::ECDSA_GEN>> IsAsymGeneration;

typedef ParamCheck<ParamName::ALGO_TYPE,
                   AlgoType,
                   true,
                   Type<AlgoType>::Equals<AlgoType::AES_GEN>> IsSymGeneration;

typedef ParamCheck<ParamName::GEN_KEY_LEN,
                   int,
                   true,
                   Type<int>::Equals<1024, 2048, 4096>> RsaKeyLenCheck;

typedef ParamCheck<ParamName::GEN_KEY_LEN,
                   int,
                   true,
                   Type<int>::Equals<1024, 2048, 3072, 4096>> DsaKeyLenCheck;

typedef ParamCheck<ParamName::GEN_KEY_LEN,
                   int,
                   true,
                   Type<int>::Equals<128, 192, 256>> AesKeyLenCheck;

typedef ParamCheck<ParamName::GEN_EC,
                   ElipticCurve,
                   true,
                   Type<ElipticCurve>::Equals<ElipticCurve::prime192v1,
                                              ElipticCurve::prime256v1,
                                              ElipticCurve::secp384r1>> EcdsaEcCheck;

typedef std::map<AlgoType, ValidatorVector> ValidatorMap;
ValidatorMap initValidators() {
    ValidatorMap validators;
    validators.emplace(AlgoType::RSA_SV, VBuilder<HashAlgoCheck, RsaPaddingCheck>::Build());
    validators.emplace(AlgoType::RSA_SV, VBuilder<HashAlgoCheck, RsaPaddingCheck>::Build());
    validators.emplace(AlgoType::DSA_SV, VBuilder<HashAlgoCheck>::Build());
    validators.emplace(AlgoType::ECDSA_SV, VBuilder<HashAlgoCheck>::Build());
    validators.emplace(AlgoType::RSA_GEN, VBuilder<RsaKeyLenCheck>::Build());
    validators.emplace(AlgoType::DSA_GEN, VBuilder<DsaKeyLenCheck>::Build());
    validators.emplace(AlgoType::ECDSA_GEN, VBuilder<EcdsaEcCheck>::Build());
    validators.emplace(AlgoType::AES_GEN, VBuilder<AesKeyLenCheck>::Build());
    validators.emplace(AlgoType::AES_CTR, VBuilder<IvSizeCheck, CtrLenCheck>::Build());
    validators.emplace(AlgoType::AES_CBC, VBuilder<IvSizeCheck>::Build());
    validators.emplace(AlgoType::AES_CFB, VBuilder<IvSizeCheck>::Build());
    validators.emplace(AlgoType::AES_GCM, VBuilder<GcmIvCheck, GcmTagCheck>::Build());
    return validators;
};
ValidatorMap g_validators = initValidators();

template <typename TypeCheck>
void validateParams(const CryptoAlgorithm& ca)
{
    // check algorithm type (Encryption/Decryption, Sign/Verify, Key generation)
    TypeCheck tc;
    tc.Check(ca);

    AlgoType at = unpack<AlgoType>(ca, ParamName::ALGO_TYPE);
    for(const auto& validator : g_validators.at(at)) {
        validator->Check(ca);
    }
}

typedef std::unique_ptr<Cipher::EvpCipherWrapper<RawBuffer>> EvpCipherPtr;

typedef std::function<void(EvpCipherPtr&, const RawBuffer& key, const RawBuffer& iv)> InitCipherFn;

// aes mode, key length in bits, encryption
typedef std::map<AlgoType, std::map<size_t, std::map<bool, InitCipherFn>>> CipherTree;

template <typename T>
void initCipher(EvpCipherPtr& ptr, const RawBuffer& key, const RawBuffer& iv)
{
    ptr.reset(new T(key, iv));
}

CipherTree initializeCipherTree()
{
    CipherTree tree;
    tree[AlgoType::AES_CBC][128][true] = initCipher<Cipher::AesCbcEncryption128>;
    tree[AlgoType::AES_CBC][192][true] = initCipher<Cipher::AesCbcEncryption192>;
    tree[AlgoType::AES_CBC][256][true] = initCipher<Cipher::AesCbcEncryption256>;

    tree[AlgoType::AES_CBC][128][false] = initCipher<Cipher::AesCbcDecryption128>;
    tree[AlgoType::AES_CBC][192][false] = initCipher<Cipher::AesCbcDecryption192>;
    tree[AlgoType::AES_CBC][256][false] = initCipher<Cipher::AesCbcDecryption256>;

    tree[AlgoType::AES_GCM][128][true] = initCipher<Cipher::AesGcmEncryption128>;
    tree[AlgoType::AES_GCM][192][true] = initCipher<Cipher::AesGcmEncryption192>;
    tree[AlgoType::AES_GCM][256][true] = initCipher<Cipher::AesGcmEncryption256>;

    tree[AlgoType::AES_GCM][128][false] = initCipher<Cipher::AesGcmDecryption128>;
    tree[AlgoType::AES_GCM][192][false] = initCipher<Cipher::AesGcmDecryption192>;
    tree[AlgoType::AES_GCM][256][false] = initCipher<Cipher::AesGcmDecryption256>;

    tree[AlgoType::AES_CTR][128][true] = initCipher<Cipher::AesCtrEncryption128>;
    tree[AlgoType::AES_CTR][192][true] = initCipher<Cipher::AesCtrEncryption192>;
    tree[AlgoType::AES_CTR][256][true] = initCipher<Cipher::AesCtrEncryption256>;

    tree[AlgoType::AES_CTR][128][false] = initCipher<Cipher::AesCtrDecryption128>;
    tree[AlgoType::AES_CTR][192][false] = initCipher<Cipher::AesCtrDecryption192>;
    tree[AlgoType::AES_CTR][256][false] = initCipher<Cipher::AesCtrDecryption256>;

    tree[AlgoType::AES_CFB][128][true] = initCipher<Cipher::AesCfbEncryption128>;
    tree[AlgoType::AES_CFB][192][true] = initCipher<Cipher::AesCfbEncryption192>;
    tree[AlgoType::AES_CFB][256][true] = initCipher<Cipher::AesCfbEncryption256>;

    tree[AlgoType::AES_CFB][128][false] = initCipher<Cipher::AesCfbDecryption128>;
    tree[AlgoType::AES_CFB][192][false] = initCipher<Cipher::AesCfbDecryption192>;
    tree[AlgoType::AES_CFB][256][false] = initCipher<Cipher::AesCfbDecryption256>;

    return tree;
}

CipherTree g_cipherTree = initializeCipherTree();

// key length in bytes
InitCipherFn selectCipher(AlgoType type, size_t key_len = 32, bool encryption = true)
{
    try {
        return g_cipherTree.at(type).at(key_len*8).at(encryption);
    } catch (const std::out_of_range&) {
        ThrowErr(Exc::Crypto::InternalError,
                 "Unsupported cipher: ",
                 static_cast<int>(type), ", ",
                 key_len, ", ",
                 encryption);
    }
}

} // anonymous namespace

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
        ThrowErr(Exc::Crypto::InternalError, "Error in hashAlgorithm value");
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
        ThrowErr(Exc::Crypto::InternalError, "Error in RSAPaddingAlgorithm value");
    }
    return rsa_padding;
}

TokenPair createKeyPairRSA(CryptoBackend backendId, const int size)
{
    EvpPkeyUPtr pkey;

    // check the parameters of functions
    if(size!=1024 && size!=2048 && size!=4096) {
        ThrowErr(Exc::Crypto::InputParam, "Error in RSA input size");
    }

    EvpPkeyCtxUPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), EVP_PKEY_CTX_free);
    if(!ctx) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_new_id function !!");
    }

    if(EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_keygen_init function !!");
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), size) <= 0) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_set_rsa_keygen_bits function !!");
    }

    EVP_PKEY *pkeyTmp = NULL;
    if(!EVP_PKEY_keygen(ctx.get(), &pkeyTmp)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_keygen function !!");
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
        ThrowErr(Exc::Crypto::InputParam, "Error in DSA input size");
    }

    /* Create the context for generating the parameters */
    EvpPkeyCtxUPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL), EVP_PKEY_CTX_free);
    if(!pctx) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_new_id function");
    }

    if(EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx.get())) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_paramgen_init function");
    }

    if(EVP_SUCCESS != EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx.get(), size)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_set_dsa_paramgen_bits(", size, ") function");
    }

    /* Generate parameters */
    EVP_PKEY *pparamTmp = NULL;
    if(EVP_SUCCESS != EVP_PKEY_paramgen(pctx.get(), &pparamTmp)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_paramgen function");
    }
    pparam = EvpPkeyUPtr(pparamTmp, EVP_PKEY_free);

    // Start to generate key
    EvpPkeyCtxUPtr kctx(EVP_PKEY_CTX_new(pparam.get(), NULL), EVP_PKEY_CTX_free);
    if(!kctx) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_SUCCESS != EVP_PKEY_keygen_init(kctx.get())) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_keygen_init function");
    }

    /* Generate the key */
    EVP_PKEY *pkeyTmp = NULL;
    if(!EVP_PKEY_keygen(kctx.get(), &pkeyTmp)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_keygen function !!");
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
        ThrowErr(Exc::Crypto::InputParam, "Error in EC type");
    }

    /* Create the context for generating the parameters */
    EvpPkeyCtxUPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free);
    if(!pctx) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_new_id function");
    }

    if(EVP_SUCCESS != EVP_PKEY_paramgen_init(pctx.get())) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_paramgen_init function");
    }

    if(EVP_SUCCESS != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), ecCurve)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid function");
    }

    /* Generate parameters */
    EVP_PKEY *pparamTmp = NULL;
    if(EVP_SUCCESS != EVP_PKEY_paramgen(pctx.get(), &pparamTmp)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_paramgen function");
    }
    pparam = EvpPkeyUPtr(pparamTmp, EVP_PKEY_free);

    // Start to generate key
    EvpPkeyCtxUPtr kctx(EVP_PKEY_CTX_new(pparam.get(), NULL), EVP_PKEY_CTX_free);
    if(!kctx) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_SUCCESS != EVP_PKEY_keygen_init(kctx.get())) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_keygen_init function");
    }

    /* Generate the key */
    EVP_PKEY *pkeyTmp = NULL;
    if(!EVP_PKEY_keygen(kctx.get(), &pkeyTmp)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_keygen function !!");
    }
    pkey = EvpPkeyUPtr(pkeyTmp, EVP_PKEY_free);

    return std::make_pair<Token, Token>(Token(backendId, DataType(KeyType::KEY_ECDSA_PRIVATE), i2d(i2d_PrivateKey_bio, pkey.get())),
                                        Token(backendId, DataType(KeyType::KEY_ECDSA_PUBLIC), i2d(i2d_PUBKEY_bio, pkey.get())));
}

Token createKeyAES(CryptoBackend backendId, const int sizeBits)
{
    // check the parameters of functions
    if(sizeBits!=128 && sizeBits!=192 && sizeBits!=256) {
        LogError("Error in AES input size");
        ThrowMsg(Exc::Crypto::InputParam, "Error in AES input size");
    }

    uint8_t key[32];
    int sizeBytes = sizeBits/8;
    if (!RAND_bytes(key, sizeBytes)) {
        LogError("Error in AES key generation");
        ThrowMsg(Exc::Crypto::InternalError, "Error in AES key generation");
    }

    return Token(backendId, DataType(KeyType::KEY_AES), CKM::RawBuffer(key, key+sizeBytes));
}

TokenPair generateAKey(CryptoBackend backendId, const CryptoAlgorithm &algorithm)
{
    validateParams<IsAsymGeneration>(algorithm);

    AlgoType keyType = unpack<AlgoType>(algorithm, ParamName::ALGO_TYPE);
    if(keyType == AlgoType::RSA_GEN || keyType == AlgoType::DSA_GEN)
    {
        int keyLength = unpack<int>(algorithm, ParamName::GEN_KEY_LEN);
        if(keyType == AlgoType::RSA_GEN)
            return createKeyPairRSA(backendId, keyLength);
        else
            return createKeyPairDSA(backendId, keyLength);
    }
    else // AlgoType::ECDSA_GEN
    {
        ElipticCurve ecType = unpack<ElipticCurve>(algorithm, ParamName::GEN_EC);
        return createKeyPairECDSA(backendId, ecType);
    }
}

Token generateSKey(CryptoBackend backendId, const CryptoAlgorithm &algorithm)
{
    validateParams<IsSymGeneration>(algorithm);

    int keySizeBits = unpack<int>(algorithm, ParamName::GEN_KEY_LEN);
    return createKeyAES(backendId, keySizeBits);
}

RawBuffer encryptDataAes(
    AlgoType type,
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv)
{
    EvpCipherPtr enc;
    selectCipher(type, key.size())(enc, key, iv);
    RawBuffer result = enc->Append(data);
    RawBuffer tmp = enc->Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
}

std::pair<RawBuffer, RawBuffer> encryptDataAesGcm(
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv,
    int tagSize,
    const RawBuffer &aad)
{
    RawBuffer tag(tagSize);
    EvpCipherPtr enc;
    selectCipher(AlgoType::AES_GCM, key.size())(enc, key, iv);

    if (!aad.empty())
        enc->AppendAAD(aad);

    RawBuffer result = enc->Append(data);
    RawBuffer tmp = enc->Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    if (0 == enc->Control(EVP_CTRL_GCM_GET_TAG, tagSize, tag.data())) {
        ThrowErr(Exc::Crypto::InternalError, "Error in AES control function. Get tag failed.");
    }
    return std::make_pair(result, tag);
}

RawBuffer encryptDataAesGcmPacked(
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv,
    int tagSize,
    const RawBuffer &aad)
{
    auto pair = encryptDataAesGcm(key, data, iv, tagSize, aad);
    std::copy(pair.second.begin(), pair.second.end(), std::back_inserter(pair.first));
    return pair.first;
}

RawBuffer decryptDataAes(
    AlgoType type,
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv)
{
    EvpCipherPtr dec;
    selectCipher(type, key.size(), false)(dec, key, iv);
    RawBuffer result = dec->Append(data);
    RawBuffer tmp = dec->Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
}

RawBuffer decryptDataAesGcm(
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv,
    const RawBuffer &tag,
    const RawBuffer &aad)
{
    EvpCipherPtr dec;
    selectCipher(AlgoType::AES_GCM, key.size(), false)(dec, key, iv);
    void *ptr = (void*)tag.data();
    if (0 == dec->Control(EVP_CTRL_GCM_SET_TAG, tag.size(), ptr)) {
        ThrowErr(Exc::Crypto::InternalError,
            "Error in AES control function. Set tag failed.");
    }
    if (!aad.empty())
        dec->AppendAAD(aad);

    RawBuffer result = dec->Append(data);
    RawBuffer tmp = dec->Finalize();
    std::copy(tmp.begin(), tmp.end(), std::back_inserter(result));
    return result;
}

RawBuffer decryptDataAesGcmPacked(
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv,
    int tagSize,
    const RawBuffer &aad)
{
    if (tagSize > static_cast<int>(data.size()))
        ThrowErr(Exc::Crypto::InputParam, "Wrong size of tag");

    auto tagPos = data.data() + data.size() - tagSize;
    return decryptDataAesGcm(
        key,
        RawBuffer(data.data(), tagPos),
        iv,
        RawBuffer(tagPos, data.data() + data.size()),
        aad);
}

RawBuffer symmetricEncrypt(const RawBuffer &key,
                           const CryptoAlgorithm &alg,
                           const RawBuffer &data)
{
    validateParams<IsEncryption>(alg);
    AlgoType keyType = unpack<AlgoType>(alg, ParamName::ALGO_TYPE);

    switch(keyType)
    {
        case AlgoType::AES_CBC:
        case AlgoType::AES_CTR:
        case AlgoType::AES_CFB:
            return encryptDataAes(keyType, key, data, unpack<RawBuffer>(alg, ParamName::ED_IV));
        case AlgoType::AES_GCM:
        {
            int tagLenBits = DEFAULT_AES_GCM_TAG_LEN;
            alg.getParam(ParamName::ED_TAG_LEN, tagLenBits);
            RawBuffer aad;
            alg.getParam(ParamName::ED_AAD, aad);
            return encryptDataAesGcmPacked(key,
                                           data,
                                           unpack<RawBuffer>(alg, ParamName::ED_IV),
                                           tagLenBits/8,
                                           aad);
        }
        default:
            break;
    }
    ThrowErr(Exc::Crypto::OperationNotSupported,
        "symmetric enc error: algorithm not recognized");
}

RawBuffer symmetricDecrypt(const RawBuffer &key,
                           const CryptoAlgorithm &alg,
                           const RawBuffer &data)
{
    validateParams<IsEncryption>(alg);
    AlgoType keyType = unpack<AlgoType>(alg, ParamName::ALGO_TYPE);

    switch(keyType)
    {
        case AlgoType::AES_CBC:
        case AlgoType::AES_CTR:
        case AlgoType::AES_CFB:
            return decryptDataAes(keyType, key, data, unpack<RawBuffer>(alg, ParamName::ED_IV));
        case AlgoType::AES_GCM:
        {
            int tagLenBits = DEFAULT_AES_GCM_TAG_LEN;
            alg.getParam(ParamName::ED_TAG_LEN, tagLenBits);
            RawBuffer aad;
            alg.getParam(ParamName::ED_AAD, aad);
            return decryptDataAesGcmPacked(key,
                                           data,
                                           unpack<RawBuffer>(alg, ParamName::ED_IV),
                                           tagLenBits/8,
                                           aad);
        }
        default:
            break;
    }
    ThrowErr(Exc::Crypto::InputParam, "symmetric dec error: algorithm not recognized");
}

RawBuffer sign(EVP_PKEY *pkey,
    const CryptoAlgorithm &alg,
    const RawBuffer &message)
{
    validateParams<IsSignVerify>(alg);

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
//        ThrowErr(CryptoService::Exception::Crypto_internal, "Error in private key type");
//    }
//
//    if(privateKey.getType()==KeyType::KEY_RSA_PRIVATE) {
//        rsa_padding = getRsaPadding(padAlgo);
//    }

    if (NULL == pkey) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_keygen function");
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
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_PKEY_sign_init(pctx.get()) != EVP_SUCCESS) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_sign_init function");
    }

    /* Set padding algorithm */
    if(EVP_PKEY_type(privKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx.get(), rsa_padding)) {
            ThrowErr(Exc::Crypto::InternalError,
                     "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    /* Finalize the Sign operation */
    /* First call EVP_PKEY_sign with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    size_t slen;
    if(EVP_SUCCESS != EVP_PKEY_sign(pctx.get(), NULL, &slen, message.data(), message.size())) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_sign function");
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

    ThrowErr(Exc::Crypto::InputParam, "Error in EVP_PKEY_sign function. Input param error.");
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
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_MD_CTX_create function");
    }

    if(EVP_SUCCESS != EVP_DigestSignInit(mdctx.get(), &pctx, md_algo, NULL, privKey)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_DigestSignInit function");
    }

    /* Set padding algorithm */
    if(EVP_PKEY_type(privKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    /* Call update with the message */
    if(EVP_SUCCESS != EVP_DigestSignUpdate(mdctx.get(), message.data(), message.size())) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_DigestSignUpdate function");
    }

    /* Finalize the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    size_t slen;
    if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx.get(), NULL, &slen)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_DigestSignFinal function");
    }

    /* Allocate memory for the signature based on size in slen */
    RawBuffer sig(slen);

    /* Obtain the signature */
    if(EVP_SUCCESS != EVP_DigestSignFinal(mdctx.get(), sig.data(), &slen)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_DigestSignFinal function");
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
    validateParams<IsSignVerify>(alg);

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
//        ThrowErr(CryptoService::Exception::Crypto_internal, "Error in private key type");
//    }
//
//    if(publicKey.getType()==KeyType::KEY_RSA_PUBLIC) {
//        rsa_padding = getRsaPadding(padAlgo);
//    }

//    auto shrPKey = publicKey.getEvpShPtr();
    if (NULL == pkey) {
        ThrowErr(Exc::Crypto::InternalError, "Error in getEvpShPtr function");
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
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_new function");
    }

    if(EVP_PKEY_verify_init(pctx.get()) != EVP_SUCCESS) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_verify_init function");
    }

    /* Set padding algorithm  */
    if(EVP_PKEY_type(pubKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx.get(), rsa_padding)) {
            ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
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
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_MD_CTX_create function");
    }

    if(EVP_SUCCESS != EVP_DigestVerifyInit(mdctx.get(), &pctx, md_algo, NULL, pubKey)) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_DigestVerifyInit function");
    }

    if(EVP_PKEY_type(pubKey->type) == EVP_PKEY_RSA) {
        if(EVP_SUCCESS != EVP_PKEY_CTX_set_rsa_padding(pctx, rsa_padding)) {
            ThrowErr(Exc::Crypto::InternalError, "Error in EVP_PKEY_CTX_set_rsa_padding function");
        }
    }

    if(EVP_SUCCESS != EVP_DigestVerifyUpdate(mdctx.get(), message.data(), message.size()) ) {
        ThrowErr(Exc::Crypto::InternalError, "Error in EVP_DigestVerifyUpdate function");
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
