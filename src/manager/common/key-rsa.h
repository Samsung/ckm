/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 *
 *
 * @file        key-rsa.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of keys.
 */
#pragma once

#include <memory>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include <generic-key.h>

namespace {

const char PEM_FIRST_CHAR = '-';
typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

} // namespace anonymous

namespace CKM {

class KeyRSA : public GenericKey {
public:
    typedef int(*I2D_FUNCTION_PTR)(BIO*, RSA*);

    static RSA* RSA_dup(RSA *rsa) {
        if (rsa)
            RSA_up_ref(rsa);
        return rsa;
    }

    KeyRSA(RSA *rsa)
      : m_rsa(RSA_dup(rsa))
    {}

    KeyRSA()
      : m_rsa(NULL)
    {}

    virtual bool empty() const {
        return m_rsa == NULL;
    }

    virtual ~KeyRSA() {
        RSA_free(m_rsa);
    }

    virtual RawBuffer extractDER(I2D_FUNCTION_PTR ptr) const {
        if (NULL == m_rsa)
            return RawBuffer();

        BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

        if (NULL == bio.get())
            return RawBuffer();

        if (0 == ptr(bio.get(), m_rsa))
            return RawBuffer();

        RawBuffer out(8192);

        int ret = BIO_read(bio.get(), out.data(), out.size());
        if (ret <= 0) {
            return RawBuffer();
        }

        out.resize(ret);
        return out;
    }

    EVP_PKEY *getEVPKEY() const {
        if (m_rsa == NULL)
            return NULL;
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, m_rsa);
        return pkey;
    }

    RSA *getRSA() {
        return m_rsa;
    }

protected:
    RSA *m_rsa;
};


class KeyRSAPublic : public KeyRSA {
public:
    KeyRSAPublic(){}

    KeyRSAPublic(RSA *rsa)
      : KeyRSA(rsa)
    {}

    KeyRSAPublic(const RawBuffer &data, const std::string &password)
    {
        char *pass = NULL;
        std::string passtmp(password);

        if (!passtmp.empty()) {
            pass = const_cast<char*>(passtmp.c_str());
        }

        if (data[0] == PEM_FIRST_CHAR) {
            BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
            if (NULL == bio.get())
                return;
            BIO_write(bio.get(), data.data(), data.size());
            m_rsa = PEM_read_bio_RSA_PUBKEY(bio.get(), NULL, NULL, pass);
        } else {
            // First we will try to read der file
            const unsigned char *p = static_cast<const unsigned char*>(data.data());
            m_rsa = d2i_RSA_PUBKEY(NULL, &p, data.size());
            if (m_rsa == NULL) {
                // This is internal der format used by openssl?
                BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
                BIO_write(bio.get(), data.data(), data.size());
                m_rsa = d2i_RSAPublicKey_bio(bio.get(), NULL);
            }
        }
    }

    KeyRSAPublic(const KeyRSAPublic &second)
      : KeyRSA(second.m_rsa)
    {}

    KeyRSAPublic(KeyRSAPublic &&second) {
        m_rsa = second.m_rsa;
        second.m_rsa = NULL;
    }

    KeyRSAPublic& operator=(const KeyRSAPublic &second) {
        if (this == &second)
            return *this;
        RSA_free(m_rsa);
        m_rsa = RSA_dup(second.m_rsa);
        return *this;
    }

    KeyRSAPublic& operator=(KeyRSAPublic &&second) {
        if (this == &second)
            return *this;
        m_rsa = second.m_rsa;
        second.m_rsa = NULL;
        return *this;
    }

    virtual RawBuffer getDER() const {
        return extractDER(i2d_RSAPublicKey_bio);
    }

    virtual KeyType getType() const {
        return KeyType::KEY_RSA_PUBLIC;
    }
};

class KeyRSAPrivate : public KeyRSA {
public:
    KeyRSAPrivate(){}

    KeyRSAPrivate(RSA *rsa)
      : KeyRSA(rsa)
    {}

    KeyRSAPrivate(const KeyRSAPrivate &second)
      : KeyRSA(second.m_rsa)
    {}

    KeyRSAPrivate(KeyRSAPrivate &&second) {
        m_rsa = second.m_rsa;
        second.m_rsa = NULL;
    }

    KeyRSAPrivate(const RawBuffer &data, const std::string &password)
    {
        char *pass = NULL;
        std::string passtmp(password);

        if (!passtmp.empty()) {
            pass = const_cast<char*>(passtmp.c_str());
        }

        if (data[0] == PEM_FIRST_CHAR) {
            BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
            if (NULL == bio.get())
                return;
            BIO_write(bio.get(), data.data(), data.size());
            m_rsa = PEM_read_bio_RSAPrivateKey(bio.get(), NULL, NULL, pass);
        } else {
            BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
            if (NULL == bio.get())
                return;
            BIO_write(bio.get(), data.data(), data.size());
            m_rsa = d2i_RSAPrivateKey_bio(bio.get(), NULL);
        }
    }

    KeyRSAPrivate& operator=(const KeyRSAPrivate &second) {
        if (this == &second)
            return *this;
        RSA_free(m_rsa);
        m_rsa = RSA_dup(second.m_rsa);
        return *this;
    }

    KeyRSAPrivate& operator=(KeyRSAPrivate &&second) {
        if (this == &second)
            return *this;
        RSA_free(m_rsa);
        m_rsa = second.m_rsa;
        second.m_rsa = NULL;
        return *this;
    }

    virtual RawBuffer getDER() const {
        return extractDER(i2d_RSAPrivateKey_bio);
    }

    virtual KeyType getType() const {
        return KeyType::KEY_RSA_PRIVATE;
    }

};

} // namespace CKM

