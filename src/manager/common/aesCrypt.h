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

#pragma once

#include <string>

#include <dpl/noncopyable.h>
#include <dpl/exception.h>

#include <ckm/ckm-type.h>

/*
 * Taken from openssl/ossl_typ.h
 */
struct evp_cipher_st;
typedef evp_cipher_st EVP_CIPHER;
struct evp_cipher_ctx_st;
typedef evp_cipher_ctx_st EVP_CIPHER_CTX;
struct engine_st;
typedef engine_st ENGINE;

namespace CKM {

class CryptoAlgConf
{
    public:
        class Exception
        {
            public:
                DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
                DECLARE_EXCEPTION_TYPE(Base, InternalError)
        };

        CryptoAlgConf(const EVP_CIPHER *cipher);
        CryptoAlgConf(const EVP_CIPHER *cipher, std::string &password);
        ~CryptoAlgConf();

        const EVP_CIPHER *getCipher(void);
        void setKey(const RawBuffer &key);
        void setIV(const RawBuffer &iv);
        void setSalt(const RawBuffer &salt); // TODO: not used yet
        RawBuffer getKey(void);
        RawBuffer getIV(void);
        RawBuffer getSalt(void);
        void generateKey(std::string &password, bool use_iv = false);
        void generateRandIV(void);
        std::size_t maxBufLen(std::size_t len);

    private:
        RawBuffer m_key;
        RawBuffer m_iv;
        RawBuffer m_salt; // TODO:  not used yet
        const EVP_CIPHER *m_cipher;
        std::size_t m_keyLen;
        std::size_t m_ivLen;
        std::size_t m_saltLen;
        int m_pkcs5_password_iter;

        void preinit(const EVP_CIPHER *cipher);
};

enum class AESCryptMode : int {
    ENCODER,
    DECODER
};

class AesCrypt : public CKM::Noncopyable
{
    public:
        class Exception
        {
            public:
                DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
                DECLARE_EXCEPTION_TYPE(Base, InternalError)
        };

        AesCrypt(AESCryptMode mode, std::string password);
        ~AesCrypt();

        void reset(void);
        RawBuffer finalize(void);
        RawBuffer get(void);
        int append(const RawBuffer &data);
        AESCryptMode getMode(void);
        CryptoAlgConf conf;

    private:
        EVP_CIPHER_CTX *m_ctx;
        RawBuffer m_buf;
        bool m_initialized;
        bool m_finalized;
        int m_bufWritePos;
        AESCryptMode m_mode;
        bool m_padding;

        int (*m_fInit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv);
        int (*m_fUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                         const unsigned char *in, int inl);
        int (*m_fFinal)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
};

class AesEncrypt : public AesCrypt
{
    public:
        AesEncrypt();
        AesEncrypt(std::string password);
        ~AesEncrypt();
};

class AesDecrypt : public AesCrypt
{
    public:
        AesDecrypt();
        AesDecrypt(std::string password);
        ~AesDecrypt();
};

} // namespace CKM

