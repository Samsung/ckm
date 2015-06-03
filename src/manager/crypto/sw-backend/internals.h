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
 * @file       internals.h
 * @author
 * @version    1.0
 */
#pragma once

#include <key-impl.h>
#include <certificate-impl.h>
#include <ckm/ckm-type.h>
#include <openssl/evp.h>
#include <token.h>

#define EVP_SUCCESS 1	// DO NOTCHANGE THIS VALUE
#define EVP_FAIL    0	// DO NOTCHANGE THIS VALUE

#define CKM_CRYPTO_INIT_SUCCESS 1
#define CKM_CRYPTO_CREATEKEY_SUCCESS 2
#define CKM_VERIFY_CHAIN_SUCCESS 5
#define NOT_DEFINED -1

namespace CKM {
namespace Crypto {
namespace SW {
namespace Internals {

// During initialization, FIPS_MODE and the entropy source are set
// and system certificates are loaded to memory.
//    FIPS_MODE - ON, OFF(Default)
//    entropy source - /dev/random,/dev/urandom(Default)
int initialize();

TokenPair createKeyPairRSA(CryptoBackend backendId, const int size);
TokenPair createKeyPairDSA(CryptoBackend backendId, const int size);
TokenPair createKeyPairECDSA(CryptoBackend backendId, ElipticCurve type1);
Token     createKeyAES(CryptoBackend backendId, const int sizeBits);

RawBuffer sign(EVP_PKEY *pkey,
    const CryptoAlgorithm &alg,
    const RawBuffer &message);

int verify(EVP_PKEY *pkey,
    const CryptoAlgorithm &alg,
    const RawBuffer &message,
    const RawBuffer &signature);

const EVP_MD *getMdAlgo(const HashAlgorithm hashAlgo);
int getRsaPadding(const RSAPaddingAlgorithm padAlgo);

RawBuffer signMessage(EVP_PKEY *privKey,
    const RawBuffer &message,
    const int rsa_padding);

RawBuffer digestSignMessage(EVP_PKEY *privKey,
    const RawBuffer &message,
    const EVP_MD *md_algo,
    const int rsa_padding);

int verifyMessage(EVP_PKEY *pubKey,
    const RawBuffer &message,
    const RawBuffer &signature,
    const int rsa_padding);

int digestVerifyMessage(EVP_PKEY *pubKey,
    const RawBuffer &message,
    const RawBuffer &signature,
    const EVP_MD *md_algo,
    const int rsa_padding);

} // namespace Internals
} // namespace SW
} // namespace Crypto
} // namespace CKM

