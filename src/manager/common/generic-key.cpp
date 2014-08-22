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
 * @file        generic-key.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Key implementation.
 */
#include <string.h>

#include <functional>
#include <memory>
#include <sstream>
#include <ios>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <dpl/log/log.h>

#include <ckm/ckm-type.h>
#include <generic-key.h>

namespace CKM {
namespace {

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

int passcb(char *buff, int size, int rwflag, void *userdata) {
    (void) rwflag;
    Password *ptr = static_cast<Password*>(userdata);
    if (ptr == NULL)
        return 0;
    if (ptr->empty())
        return 0;
    if (static_cast<int>(ptr->size()) > size)
        return 0;
    memcpy(buff, ptr->c_str(), ptr->size());
    return ptr->size();
}

typedef int(*I2D_CONV)(BIO*, EVP_PKEY*);

CKM::RawBuffer i2d(I2D_CONV fun, EVP_PKEY* pkey) {
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (NULL == pkey) {
        LogDebug("You are trying to read empty key!");
        return RawBuffer();
    }

    if (NULL == bio.get()) {
        LogError("Error in memory allocation! Function: BIO_new.");
        return RawBuffer();
    }

    if (1 != fun(bio.get(), pkey)) {
        LogError("Error in conversion EVP_PKEY to der");
        return RawBuffer();
    }

    CKM::RawBuffer output(8196);

    int size = BIO_read(bio.get(), output.data(), output.size());

    if (size <= 0) {
        LogError("Error in BIO_read: " << size);
        return RawBuffer();
    }

    output.resize(size);
    return output;
}

} // anonymous namespace

GenericKey::GenericKey()
  : m_pkey(NULL, EVP_PKEY_free)
  , m_type(KeyType::KEY_NONE)
{}

GenericKey::GenericKey(const GenericKey &second) {
    m_pkey = second.m_pkey;
    m_type = second.m_type;
}

GenericKey::GenericKey(const RawBuffer &buf, const Password &password)
  : m_pkey(NULL, EVP_PKEY_free)
  , m_type(KeyType::KEY_NONE)
{
    bool isPrivate = false;
    EVP_PKEY *pkey = NULL;
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    LogDebug("Start to parse key:");
//    printDER(buf);

    if (buf[0] != '-') {
        BIO_write(bio.get(), buf.data(), buf.size());
        pkey = d2i_PUBKEY_bio(bio.get(), NULL);
        isPrivate = false;
        LogDebug("Trying d2i_PUBKEY_bio Status: " << (void*)pkey);
    }

    if (!pkey && buf[0] != '-') {
        BIO_reset(bio.get());
        BIO_write(bio.get(), buf.data(), buf.size());
        pkey = d2i_PrivateKey_bio(bio.get(), NULL);
        isPrivate = true;
        LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
    }

    if (!pkey && buf[0] == '-') {
        BIO_reset(bio.get());
        BIO_write(bio.get(), buf.data(), buf.size());
        pkey = PEM_read_bio_PUBKEY(bio.get(), NULL, passcb, const_cast<Password*>(&password));
        isPrivate = false;
        LogDebug("PEM_read_bio_PUBKEY Status: " << (void*)pkey);
    }

    if (!pkey && buf[0] == '-') {
        BIO_reset(bio.get());
        BIO_write(bio.get(), buf.data(), buf.size());
        pkey = PEM_read_bio_PrivateKey(bio.get(), NULL, passcb, const_cast<Password*>(&password));
        isPrivate = true;
        LogDebug("PEM_read_bio_PrivateKey Status: " << (void*)pkey);
    }

    if (!pkey) {
        LogError("Failed to parse key");
        return;
    }

    m_pkey.reset(pkey, EVP_PKEY_free);

    int type = EVP_PKEY_type(pkey->type);

    if (type == EVP_PKEY_RSA) {
        m_type = isPrivate ? KeyType::KEY_RSA_PRIVATE : KeyType::KEY_RSA_PUBLIC;
    }

    if (type == EVP_PKEY_EC) {
        m_type = isPrivate ? KeyType::KEY_ECDSA_PRIVATE : KeyType::KEY_ECDSA_PUBLIC;
    }
    LogDebug("KeyType is: " << (int)m_type << " isPrivate: " << isPrivate);
}

GenericKey::GenericKey(EvpShPtr pkey, KeyType type)
  : m_pkey(pkey)
  , m_type(type)
{
    if (type == KeyType::KEY_RSA_PRIVATE || type == KeyType::KEY_RSA_PUBLIC)
        if (EVP_PKEY_RSA != EVP_PKEY_type(pkey->type)) {
            m_pkey.reset();
            m_type = KeyType::KEY_NONE;
        }
    if (type == KeyType::KEY_ECDSA_PRIVATE || type == KeyType::KEY_ECDSA_PUBLIC)
        if (EVP_PKEY_EC != EVP_PKEY_type(pkey->type)) {
            m_pkey.reset();
            m_type = KeyType::KEY_NONE;
        }
}

bool GenericKey::empty() const {
    return m_pkey.get() == NULL;
}

GenericKey::EvpShPtr GenericKey::getEvpShPtr() const {
    return m_pkey;
}

KeyType GenericKey::getType() const {
    return m_type;
}

RawBuffer GenericKey::getDERPRV() const {
    return i2d(i2d_PrivateKey_bio, m_pkey.get());
}

RawBuffer GenericKey::getDERPUB() const {
    return i2d(i2d_PUBKEY_bio, m_pkey.get());
}

RawBuffer GenericKey::getDER() const {
    if (m_type == KeyType::KEY_ECDSA_PRIVATE || m_type == KeyType::KEY_RSA_PRIVATE) {
        return getDERPRV();
    } else if (m_type == KeyType::KEY_RSA_PUBLIC || m_type == KeyType::KEY_ECDSA_PUBLIC) {
        return getDERPUB();
    }
    return RawBuffer();
}

KeyShPtr Key::create(const RawBuffer &raw, const Password &password) {
    try {
        KeyShPtr output = std::make_shared<GenericKey>(raw, password);
        if (output->empty())
            output.reset();
        return output;
    } catch (const std::bad_alloc &) {
        LogDebug("Bad alloc was catch during GenericKey creation");
    } catch (...) {
        LogError("Critical error: Unknown exception was caught during GenericKey creation");
    }
    return KeyShPtr();
}

} // namespace CKM

