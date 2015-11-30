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

#include <ckm/ckm-type.h>
#include <openssl/evp.h>
#include <sw-backend/obj.h>

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

// TODO replace it with DataContainer
struct Data {
    DataType type;
    RawBuffer buffer;
};

typedef std::pair<Data,Data> DataPair;

DataPair createKeyPairRSA(const int size);
DataPair createKeyPairDSA(const int size);
DataPair createKeyPairECDSA(ElipticCurve type1);
Data     createKeyAES(const int sizeBits);

DataPair generateAKey(const CryptoAlgorithm &algorithm);
Data generateSKey(const CryptoAlgorithm &algorithm);

RawBuffer symmetricEncrypt(const RawBuffer &key,
                           const CryptoAlgorithm &alg,
                           const RawBuffer &data);
RawBuffer symmetricDecrypt(const RawBuffer &key,
                           const CryptoAlgorithm &alg,
                           const RawBuffer &cipher);
RawBuffer asymmetricEncrypt(const EvpShPtr &key,
                            const CryptoAlgorithm &alg,
                            const RawBuffer &data);
RawBuffer asymmetricDecrypt(const EvpShPtr &key,
                            const CryptoAlgorithm &alg,
                            const RawBuffer &data);

std::pair<RawBuffer, RawBuffer> encryptDataAesGcm(const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv,
    int tagSize,
    const RawBuffer &aad = RawBuffer());

RawBuffer decryptDataAesGcm(const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv,
    const RawBuffer &tag,
    const RawBuffer &aad = RawBuffer());

RawBuffer encryptDataAes(AlgoType type,
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv);

RawBuffer decryptDataAes(AlgoType type,
    const RawBuffer &key,
    const RawBuffer &data,
    const RawBuffer &iv);

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

bool verifyBinaryData(DataType dataType, const RawBuffer &buffer);

} // namespace Internals
} // namespace SW
} // namespace Crypto
} // namespace CKM

