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
 * @file        key-impl.cpp
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
#include <key-impl.h>

namespace CKM {
namespace {

typedef std::unique_ptr<BIO, std::function<void(BIO*)>> BioUniquePtr;

int passcb(char *buff, int size, int rwflag, void *userdata)
{
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

CKM::RawBuffer i2d(I2D_CONV fun, EVP_PKEY* pkey)
{
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

KeyImpl::KeyImpl()
  : m_pkey(NULL, EVP_PKEY_free)
  , m_type(KeyType::KEY_NONE)
{
}

KeyImpl::KeyImpl(const KeyImpl &second)
{
    m_pkey = second.m_pkey;
    m_type = second.m_type;
}

KeyImpl::KeyImpl(const RawBuffer &buf, const Password &password) :
    m_pkey(NULL, EVP_PKEY_free),
    m_type(KeyType::KEY_NONE)
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
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), buf.data(), buf.size());
        pkey = d2i_PrivateKey_bio(bio.get(), NULL);
        isPrivate = true;
        LogDebug("Trying d2i_PrivateKey_bio Status: " << (void*)pkey);
    }

    if (!pkey && buf[0] == '-') {
        (void)BIO_reset(bio.get());
        BIO_write(bio.get(), buf.data(), buf.size());
        pkey = PEM_read_bio_PUBKEY(bio.get(), NULL, passcb, const_cast<Password*>(&password));
        isPrivate = false;
        LogDebug("PEM_read_bio_PUBKEY Status: " << (void*)pkey);
    }

    if (!pkey && buf[0] == '-') {
        (void)BIO_reset(bio.get());
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

    switch (EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_RSA:
            m_type = isPrivate ? KeyType::KEY_RSA_PRIVATE : KeyType::KEY_RSA_PUBLIC;
            break;

        case EVP_PKEY_DSA:
            m_type = isPrivate ? KeyType::KEY_DSA_PRIVATE : KeyType::KEY_DSA_PUBLIC;
            break;

        case EVP_PKEY_EC:
            m_type = isPrivate ? KeyType::KEY_ECDSA_PRIVATE : KeyType::KEY_ECDSA_PUBLIC;
            break;
    }
    LogDebug("KeyType is: " << (int)m_type << " isPrivate: " << isPrivate);
}

KeyImpl::KeyImpl(EvpShPtr pkey, KeyType type) :
    m_pkey(pkey),
    m_type(type)
{
    int expected_type = EVP_PKEY_NONE;
    switch (type) {
        case KeyType::KEY_RSA_PRIVATE:
        case KeyType::KEY_RSA_PUBLIC:
            expected_type = EVP_PKEY_RSA;
            break;

        case KeyType::KEY_DSA_PRIVATE:
        case KeyType::KEY_DSA_PUBLIC:
            expected_type = EVP_PKEY_DSA;
            break;

        case KeyType::KEY_AES:
            LogError("Error, AES keys are not supported yet.");
            break;

        case KeyType::KEY_ECDSA_PRIVATE:
        case KeyType::KEY_ECDSA_PUBLIC:
            expected_type = EVP_PKEY_EC;
            break;

        default:
            LogError("Unknown key type provided.");
            break;
    }

    // verify if actual key type matches the expected tpe
    int given_key_type = EVP_PKEY_type(pkey->type);
    if (given_key_type == EVP_PKEY_NONE || expected_type != given_key_type) {
        m_pkey.reset();
        m_type = KeyType::KEY_NONE;
    }
}

bool KeyImpl::empty() const
{
    return m_pkey.get() == NULL;
}

KeyImpl::EvpShPtr KeyImpl::getEvpShPtr() const
{
    return m_pkey;
}

KeyType KeyImpl::getType() const
{
    return m_type;
}

RawBuffer KeyImpl::getDERPRV() const
{
    return i2d(i2d_PrivateKey_bio, m_pkey.get());
}

RawBuffer KeyImpl::getDERPUB() const
{
    return i2d(i2d_PUBKEY_bio, m_pkey.get());
}

RawBuffer KeyImpl::getDER() const
{
    switch (m_type) {
        case KeyType::KEY_RSA_PRIVATE:
        case KeyType::KEY_DSA_PRIVATE:
        case KeyType::KEY_ECDSA_PRIVATE:
            return getDERPRV();

        case KeyType::KEY_RSA_PUBLIC:
        case KeyType::KEY_DSA_PUBLIC:
        case KeyType::KEY_ECDSA_PUBLIC:
            return getDERPUB();

        default:
            break;
    }
    return RawBuffer();
}

KeyShPtr Key::create(const RawBuffer &raw, const Password &password)
{
    try {
        KeyShPtr output = std::make_shared<KeyImpl>(raw, password);
        if (output->empty())
            output.reset();
        return output;
    } catch (const std::bad_alloc &) {
        LogDebug("Bad alloc was catch during KeyImpl creation");
    } catch (...) {
        LogError("Critical error: Unknown exception was caught during KeyImpl creation");
    }
    return KeyShPtr();
}

} // namespace CKM

