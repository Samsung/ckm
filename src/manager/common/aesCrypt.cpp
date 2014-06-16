/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <features.h>

#include <dpl/log/log.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <aesCrypt.h>

namespace CKM {

CryptoAlgConf::CryptoAlgConf(const EVP_CIPHER *cipher) :
    m_key(EVP_MAX_KEY_LENGTH),
    m_salt(PKCS5_SALT_LEN)
{
    preinit(cipher);
}

CryptoAlgConf::CryptoAlgConf(const EVP_CIPHER *cipher, std::string &password) :
    m_key(EVP_MAX_KEY_LENGTH),
    m_salt(PKCS5_SALT_LEN)
{
    preinit(cipher);
    if (not password.empty())
        generateKey(password);
}

CryptoAlgConf::~CryptoAlgConf()
{
}

const EVP_CIPHER *CryptoAlgConf::getCipher(void)
{
    return m_cipher;
}

void CryptoAlgConf::generateKey(std::string &password, bool use_iv)
{
    int ret = -1;

    if (password.empty()) {
        ThrowMsg(Exception::InternalError, "Password is empty.");
    }
    if (not use_iv)
        generateRandIV();
    ret = PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), NULL, 0,
                                 m_pkcs5_password_iter, m_keyLen,
                                 m_key.data());
    if (ret != 1) {
        ThrowMsg(Exception::InternalError,
                 "PKCS5_PBKDF2_HMAC_SHA1 has failed.");
    }
}

void CryptoAlgConf::generateRandIV()
{
    RawBuffer civ(EVP_MAX_IV_LENGTH);

    if (RAND_bytes(civ.data(), civ.size()) != 1) {
        ThrowMsg(Exception::InternalError,
                 "RAND_bytes failed to generate IV.");
    }
    m_iv = civ;
}

void CryptoAlgConf::setKey(const RawBuffer &key)
{
    if (key.size() != m_keyLen) {
        ThrowMsg(Exception::InternalError, "Invalid key length.");
    }
    m_key = key;
}

void CryptoAlgConf::setIV(const RawBuffer &iv)
{
    if ((iv.size() != m_ivLen) && (iv.size() != 0)) {
        ThrowMsg(Exception::InternalError, "Invalid IV length.");
    }
    m_iv = iv;
}

void CryptoAlgConf::setSalt(const RawBuffer &salt)
{
    if (salt.size() != m_saltLen) {
        ThrowMsg(Exception::InternalError, "Invalid salt length.");
    }
    m_salt = salt;
}

RawBuffer CryptoAlgConf::getKey()
{
    return m_key;
}

RawBuffer CryptoAlgConf::getIV()
{
    return m_iv;
}

RawBuffer CryptoAlgConf::getSalt()
{
    return m_salt;
}

void CryptoAlgConf::preinit(const EVP_CIPHER *cipher)
{
    m_cipher = cipher;
    if (m_cipher == nullptr)
        m_cipher = EVP_aes_256_cbc();
    m_keyLen = EVP_CIPHER_key_length(m_cipher);
    m_ivLen = EVP_CIPHER_iv_length(m_cipher);
    m_saltLen = PKCS5_SALT_LEN;
    m_key.resize(m_keyLen);
    m_pkcs5_password_iter = 1024;
    generateRandIV();
}

std::size_t CryptoAlgConf::maxBufLen(std::size_t len)
{
    return len + EVP_CIPHER_block_size(m_cipher);
}

/******************************************************************************
 *****************************************************************************/

AesCrypt::AesCrypt(AESCryptMode mode, std::string password) :
    conf(nullptr, password)
{
    m_ctx = nullptr;
    if ((mode != AESCryptMode::ENCODER) && (mode != AESCryptMode::DECODER)) {
        ThrowMsg(Exception::InternalError,
                 "Unknown mode of crypto operations.");
    } else
        m_mode = mode;
    m_initialized = false;
    m_finalized = false;
    m_padding = true;
    if (m_mode == AESCryptMode::ENCODER) {
        m_fInit = EVP_EncryptInit_ex;
        m_fUpdate = EVP_EncryptUpdate;
        m_fFinal = EVP_EncryptFinal_ex;
    } else {
        m_fInit = EVP_DecryptInit_ex;
        m_fUpdate = EVP_DecryptUpdate;
        m_fFinal = EVP_DecryptFinal_ex;
    }
}

AesCrypt::~AesCrypt()
{
    EVP_CIPHER_CTX_free(m_ctx);
}

void AesCrypt::reset()
{
    int ret = -1;

    if (m_initialized) {
        EVP_CIPHER_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
    m_initialized = false;
    m_finalized = false;
    m_ctx = EVP_CIPHER_CTX_new();
    if (m_ctx == nullptr) {
        ThrowMsg(Exception::InternalError,
                 "Failed to alloc security context.");
    }
    ret = m_fInit(m_ctx, conf.getCipher(), NULL, conf.getKey().data(),
                  conf.getIV().data());
    if (ret != 1) {
        ThrowMsg(Exception::InternalError,
                 "Failed to initialize encryption in openssl.");
    }
    if (m_padding)
        EVP_CIPHER_CTX_set_padding(m_ctx, 1);
    m_bufWritePos = 0;
    m_buf.clear();
    m_initialized = true;
}

RawBuffer AesCrypt::finalize()
{
    int ret = -1;
    int outlf;

    if (not m_initialized) {
        ThrowMsg(Exception::InternalError, "Not initialized.");
    }
    if (m_finalized) {
        ThrowMsg(Exception::InternalError, "Already finalized.");
    }
    if (m_buf.size() == 0) {
        ThrowMsg(Exception::InternalError,
                 "Empty buffor: append() was missing?");
    }
    m_buf.resize(conf.maxBufLen(m_bufWritePos));
    ret = m_fFinal(m_ctx, m_buf.data() + m_bufWritePos, &outlf);
    if (ret != 1) {
        ThrowMsg(Exception::InternalError,
                 "Failed to encrypt data in openssl (final)");
    }
    m_bufWritePos += outlf;
    if (0 == m_bufWritePos) {
        ThrowMsg(Exception::InternalError,
                 "No output data.");
    }
    EVP_CIPHER_CTX_free(m_ctx);
    m_ctx = nullptr;
    m_buf.resize(m_bufWritePos);
    m_initialized = false;
    m_finalized = true;

    return m_buf;
}

int AesCrypt::append(const RawBuffer &data)
{
    int ret = -1;
    int outl = -1;

    if (data.size() == 0) {
        ThrowMsg(Exception::InternalError, "Empty data.");
    }
    if (m_finalized) {
        ThrowMsg(Exception::InternalError, "Already finalized.");
    }
    if (not m_initialized)
        reset();

    m_buf.resize(conf.maxBufLen(data.size()));
    ret = m_fUpdate(m_ctx, m_buf.data() + m_bufWritePos, &outl, data.data(),
                    data.size());
    if (ret != 1) {
        ThrowMsg(Exception::InternalError,
                 "Failed to encrypt data in openssl");
    }
    m_bufWritePos += outl;

    return outl;
}

RawBuffer AesCrypt::get()
{
    if (m_finalized)
        return m_buf;
    else
        return RawBuffer();
}

AESCryptMode AesCrypt::getMode()
{
    return m_mode;
}

/******************************************************************************
 *****************************************************************************/

AesEncrypt::AesEncrypt() :
    AesCrypt(AESCryptMode::ENCODER, "")
{
}

AesEncrypt::AesEncrypt(std::string password) :
    AesCrypt(AESCryptMode::ENCODER, password)
{
}

AesEncrypt::~AesEncrypt()
{
}

/******************************************************************************
 *****************************************************************************/

AesDecrypt::AesDecrypt() :
    AesCrypt(AESCryptMode::DECODER, "")
{
}

AesDecrypt::AesDecrypt(std::string password) :
    AesCrypt(AESCryptMode::DECODER, password)
{
}

AesDecrypt::~AesDecrypt()
{
}

} // namespace CKM

