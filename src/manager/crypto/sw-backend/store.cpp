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
 * @file       store.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <memory>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include <generic-backend/exception.h>
#include <sw-backend/obj.h>
#include <sw-backend/store.h>
#include <sw-backend/internals.h>
#include <SWKeyFile.h>
#include <dpl/log/log.h>

#include <message-buffer.h>

namespace CKM {
namespace Crypto {
namespace SW {

namespace {

const int ITERATIONS = 1024;
const int KEY_LENGTH = 16; // length of AES key derived from password
const int STORE_AES_GCM_TAG_SIZE = 16; // length of AES GCM tag

// internal SW encryption scheme flags
enum EncryptionScheme {
    NONE = 0,
    PASSWORD = 1 << 0
};

template <typename T, typename ...Args>
std::unique_ptr<T> make_unique(Args&& ...args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

RawBuffer generateRandIV()
{
    RawBuffer civ(EVP_MAX_IV_LENGTH);

    if (1 != RAND_bytes(civ.data(), civ.size()))
        ThrowErr(Exc::Crypto::InternalError, "RAND_bytes failed to generate IV.");
    return civ;
}

RawBuffer passwordToKey(const Password &password, const RawBuffer &salt, size_t keySize)
{
    RawBuffer result(keySize);

    if (1 != PKCS5_PBKDF2_HMAC_SHA1(
                password.c_str(),
                password.size(),
                salt.data(),
                salt.size(),
                ITERATIONS,
                result.size(),
                result.data()))
        ThrowErr(Exc::InternalError, "PCKS5_PKKDF2_HMAC_SHA1 failed.");

    return result;
}

RawBuffer unpack(const RawBuffer& packed, const Password& pass)
{
    MessageBuffer buffer;
    buffer.Push(packed);
    int encryptionScheme = 0;
    RawBuffer data;
    buffer.Deserialize(encryptionScheme, data);

    if (encryptionScheme == 0)
        return data;

    MessageBuffer internalBuffer;
    internalBuffer.Push(data);
    RawBuffer encrypted;
    RawBuffer iv;
    RawBuffer tag;

    // serialization exceptions will be catched as CKM::Exception and will cause
    // CKM_API_ERROR_SERVER_ERROR
    internalBuffer.Deserialize(encrypted, iv, tag);

    /*
     * AES GCM will check data integrity and handle cases where:
     * - wrong password is used
     * - password is empty when it shouldn't be
     * - password is not empty when it should be
     */
    RawBuffer key = passwordToKey(pass, iv, KEY_LENGTH);

    RawBuffer ret;
    try {
        ret = Crypto::SW::Internals::decryptDataAesGcm(key, encrypted, iv, tag);
    } catch( const Exc::Crypto::InternalError& e) {
        ThrowErr(Exc::AuthenticationFailed, "Decryption with custom password failed");
    }
    return ret;
}

RawBuffer pack(const RawBuffer& data, const Password& pass)
{
    int scheme = EncryptionScheme::NONE;
    RawBuffer packed = data;
    if (!pass.empty()) {
        RawBuffer iv = generateRandIV();
        RawBuffer key = passwordToKey(pass, iv, KEY_LENGTH);

        std::pair<RawBuffer, RawBuffer> ret;
        try {
            ret = Crypto::SW::Internals::encryptDataAesGcm(key, data, iv, STORE_AES_GCM_TAG_SIZE);
        } catch( const Exc::Crypto::InternalError& e) {
            ThrowErr(Exc::AuthenticationFailed, "Encryption with custom password failed");
        }
        scheme |= EncryptionScheme::PASSWORD;

        // serialization exceptions will be catched as CKM::Exception and will cause
        // CKM_API_ERROR_SERVER_ERROR
        packed = MessageBuffer::Serialize(ret.first, iv, ret.second).Pop();
    }
    // encryption scheme + internal buffer
    return MessageBuffer::Serialize(scheme, packed).Pop();
}

} // namespace anonymous

namespace
{
const char * const DEVICE_KEY_XSD = RO_DATA_DIR "sw_key.xsd";
const char * const DEVICE_KEY_SW_FILE = RW_DATA_DIR "device_key.xml";
}

Store::Store(CryptoBackend backendId)
  : GStore(backendId)
{
    // get the device key if present
    InitialValues::SWKeyFile keyFile(DEVICE_KEY_SW_FILE);
    int rc = keyFile.Validate(DEVICE_KEY_XSD);
    if (rc == XML::Parser::PARSE_SUCCESS) {
        rc = keyFile.Parse();
        if (rc == XML::Parser::PARSE_SUCCESS)
            m_deviceKey = keyFile.getPrivKey();
        else
            // do nothing, bypass encrypted elements
            LogWarning("invalid SW key file: " << DEVICE_KEY_SW_FILE << ", parsing code: " << rc);
    } else {
        LogWarning("invalid SW key file: " << DEVICE_KEY_SW_FILE << ", validation code: " << rc);
    }
}

GObjUPtr Store::getObject(const Token &token, const Password &pass)
{
    if (token.backendId != m_backendId)
        ThrowErr(Exc::Crypto::WrongBackend, "Decider choose wrong backend!");

    RawBuffer data = unpack(token.data, pass);

    if (token.dataType.isKeyPrivate() || token.dataType.isKeyPublic())
         return make_unique<AKey>(data, token.dataType);

    if (token.dataType == DataType(DataType::KEY_AES))
         return make_unique<SKey>(data, token.dataType);

    if (token.dataType.isCertificate() || token.dataType.isChainCert())
        return make_unique<Cert>(data, token.dataType);

    if (token.dataType.isBinaryData())
        return make_unique<BData>(data, token.dataType);

    ThrowErr(Exc::Crypto::DataTypeNotSupported,
        "This type of data is not supported by openssl backend: ", (int)token.dataType);
}

TokenPair Store::generateAKey(const CryptoAlgorithm &algorithm,
                              const Password &prvPass,
                              const Password &pubPass)
{
    Internals::DataPair ret = Internals::generateAKey(algorithm);
    return std::make_pair<Token, Token>(
            Token(m_backendId, ret.first.type, pack(ret.first.buffer, prvPass)),
            Token(m_backendId, ret.second.type, pack(ret.second.buffer, pubPass)));
}

Token Store::generateSKey(const CryptoAlgorithm &algorithm, const Password &pass)
{
    Internals::Data ret = Internals::generateSKey(algorithm);
    return Token(m_backendId, ret.type, pack(ret.buffer, pass));
}

Token Store::import(const Data &data, const Password &pass)
{
    return Token(m_backendId, data.type, pack(data.data, pass));
}

Token Store::importEncrypted(const Data &data, const Password &pass, const DataEncryption &enc)
{
    if (!m_deviceKey)
        ThrowErr(Exc::Crypto::InternalError, "No device key present");

    // decrypt the AES key using device key
    CryptoAlgorithm algorithmRSAOAEP;
    algorithmRSAOAEP.setParam(ParamName::ALGO_TYPE, AlgoType::RSA_OAEP);
    Crypto::SW::SKey aesKey(m_deviceKey->decrypt(algorithmRSAOAEP, enc.encryptedKey), DataType::KEY_AES);

    // decrypt the buffer using AES key
    CryptoAlgorithm algorithmAESCBC;
    algorithmAESCBC.setParam(ParamName::ALGO_TYPE, AlgoType::AES_CBC);
    algorithmAESCBC.setParam(ParamName::ED_IV, enc.iv);
    RawBuffer rawData = aesKey.decrypt(algorithmAESCBC, data.data);
    if (!Internals::verifyBinaryData(data.type, rawData))
        ThrowErr(Exc::Crypto::InputParam, "Verification failed. Data could not be imported!");

    return Token(m_backendId, data.type, pack(rawData, pass));
}

} // namespace SW
} // namespace Crypto
} // namespace CKM
