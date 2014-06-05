/* Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        client-echo.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Key implementation.
 */
#include <memory>

#include <openssl/bio.h>
#include <openssl/pem.h>

#include <key-impl.h>

namespace {

const char PEM_FIRST_CHAR = '-';
typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

} // namespace anonymous

namespace CKM {

KeyImpl::KeyImpl()
  : m_type(KeyType::KEY_NONE)
{}

KeyImpl::KeyImpl(const KeyImpl &second)
  : m_type(second.m_type)
  , m_key(second.m_key)
{}

KeyImpl::KeyImpl(KeyImpl &&second)
  : m_type(second.m_type)
  , m_key(std::move(second.m_key))
{}

KeyImpl& KeyImpl::operator=(const KeyImpl &second) {
    m_type = second.m_type;
    m_key = second.m_key;
    return *this;
}

KeyImpl& KeyImpl::operator=(KeyImpl &&second) {
    m_type = std::move(second.m_type);
    m_key = std::move(second.m_key);
    return *this;
}

KeyImpl::KeyImpl(const RawBuffer &data, KeyType type, const std::string &password)
  : m_type(KeyType::KEY_NONE)
{
    int ret = 0;
    RSA *rsa = NULL;
    char *pass = NULL;
    std::string passtmp(password);

    if (!passtmp.empty()) {
        pass = const_cast<char *>(passtmp.c_str());
    }

    if (data[0] == PEM_FIRST_CHAR && type == KeyType::KEY_RSA_PUBLIC) {
        BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
        if (NULL == bio.get())
            return;
        BIO_write(bio.get(), data.data(), data.size());
        rsa = PEM_read_bio_RSA_PUBKEY(bio.get(), NULL, NULL, pass);
    } else if (data[0] == PEM_FIRST_CHAR && type == KeyType::KEY_RSA_PRIVATE) {
        BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
        if (NULL == bio.get())
            return;
        BIO_write(bio.get(), data.data(), data.size());
        rsa = PEM_read_bio_RSAPrivateKey(bio.get(), NULL, NULL, pass);
    } else if (type == KeyType::KEY_RSA_PUBLIC) {
        const unsigned char *p = static_cast<const unsigned char*>(data.data());
        rsa = d2i_RSA_PUBKEY(NULL, &p, data.size());
    } else if (type == KeyType::KEY_RSA_PRIVATE) {
        BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
        if (NULL == bio.get())
            return;
        BIO_write(bio.get(), data.data(), data.size());
        rsa = d2i_RSAPrivateKey_bio(bio.get(), NULL);
    } else {
        return;
    }

    if (!rsa)
        return;

    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (NULL == bio.get())
        return;

    if (type == KeyType::KEY_RSA_PUBLIC) {
        ret = i2d_RSAPublicKey_bio(bio.get(), rsa);
    } else {
        ret = i2d_RSAPrivateKey_bio(bio.get(), rsa);
    }

    if (ret == 0)
        return;

    m_key.resize(data.size());
    ret = BIO_read(bio.get(), m_key.data(), m_key.size());
    if (ret <= 0) {
        m_key.clear();
        return;
    }

    m_key.resize(ret);
    m_type = type;
}

KeyImpl::~KeyImpl(){}

} // namespace CKM

