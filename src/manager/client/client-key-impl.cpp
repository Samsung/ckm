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
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <client-key-impl.h>

namespace {

const char PEM_FIRST_CHAR = '-';

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

//KeyImpl::KeyImpl(IStream &stream) {
//    int type;
//    Deserialization::Deserialize(stream, type);
//    Deserialization::Deserialize(stream, m_key);
//    m_type = static_cast<KeyType>(type);
//}

KeyImpl::KeyImpl(const RawBuffer &data, KeyType type, const RawBuffer &password)
  : m_type(KeyType::KEY_NONE)
{
    int size = 0;
    RSA *rsa = NULL;
    char *pass = NULL;
    RawBuffer passtmp(password);

    if (!passtmp.empty()) {
        passtmp.push_back(0);
        pass = reinterpret_cast<char*>(passtmp.data());
    }

    if (data[0] == PEM_FIRST_CHAR && type == KeyType::KEY_RSA_PUBLIC) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO_write(bio, data.data(), data.size());
        rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, pass);
        BIO_free_all(bio);
    } else if (data[0] == PEM_FIRST_CHAR && type == KeyType::KEY_RSA_PRIVATE) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO_write(bio, data.data(), data.size());
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, pass);
        BIO_free_all(bio);
    } else if (type == KeyType::KEY_RSA_PUBLIC) {
        const unsigned char *p = (const unsigned char*)data.data();
        rsa = d2i_RSA_PUBKEY(NULL, &p, data.size());
    } else if (type == KeyType::KEY_RSA_PRIVATE) {
        BIO *bio = BIO_new(BIO_s_mem());
        BIO_write(bio, data.data(), data.size());
        rsa = d2i_RSAPrivateKey_bio(bio, NULL);
        BIO_free_all(bio);
    } else {
        return;
    }

    if (!rsa)
        return;

    BIO *bio = BIO_new(BIO_s_mem());

    if (type == KeyType::KEY_RSA_PUBLIC) {
        size = i2d_RSAPublicKey_bio(bio, rsa);
    } else {
        size = i2d_RSAPrivateKey_bio(bio, rsa);
    }

    if (size > 0) {
        m_key.resize(size);
        BIO_read(bio, m_key.data(), m_key.size());
        m_type = type;
    }
    BIO_free_all(bio);
}

//void KeyImpl::Serialize(IStream &stream) const {
//    Serialization::Serialize(stream, static_cast<int>(m_type));
//    Serialization::Serialize(stream, m_key);
//}

KeyImpl::~KeyImpl(){}

} // namespace CKM

