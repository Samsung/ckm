#pragma once

#include <memory>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include <generic-key.h>

namespace CKM {

class KeyECDSA : public GenericKey {
public:
    KeyECDSA()
      : m_ecdsa(NULL)
    {}

    KeyECDSA(void *ecdsa)
      : m_ecdsa(ecdsa)
    {}

    virtual bool empty() const {
        return m_ecdsa == NULL;
    }

    virtual ~KeyECDSA() {
        free(m_ecdsa);
    }

    EVP_PKEY *getEVPKEY() const {
        return NULL;
    }

protected:
    void *m_ecdsa;
};


class KeyECDSAPublic : public KeyECDSA {
public:
    KeyECDSAPublic(){}

    KeyECDSAPublic(void *ecdsa)
      : KeyECDSA(ecdsa)
    {}

    KeyECDSAPublic(const RawBuffer &data, const std::string &password)
    {
        (void) data;
        (void) password;
    }

    KeyECDSAPublic(const KeyECDSAPublic &second)
      : KeyECDSA(second.m_ecdsa)
    {}

    KeyECDSAPublic(KeyECDSAPublic &&second) {
        (void) second;
    }

    KeyECDSAPublic& operator=(const KeyECDSAPublic &second) {
        (void) second;
        return *this;
    }

    KeyECDSAPublic& operator=(KeyECDSAPublic &&second) {
        (void) second;
        return *this;
    }

    virtual RawBuffer getDER() const {
        return RawBuffer();
    }

    virtual KeyType getType() const {
        return KeyType::KEY_ECDSA_PUBLIC;
    }
};

class KeyECDSAPrivate : public KeyECDSA {
public:
    KeyECDSAPrivate(){}

    KeyECDSAPrivate(void *ecdsa)
      : KeyECDSA(ecdsa)
    {}

    KeyECDSAPrivate(const KeyECDSAPrivate &second)
      : KeyECDSA(second.m_ecdsa)
    {}

    KeyECDSAPrivate(KeyECDSAPrivate &&second) {
        (void) second;
    }

    KeyECDSAPrivate(const RawBuffer &data, const std::string &password)
    {
        (void) data;
        (void) password;
    }

    KeyECDSAPrivate& operator=(const KeyECDSAPrivate &second) {
        (void) second;
        return *this;
    }

    KeyECDSAPrivate& operator=(KeyECDSAPrivate &&second) {
        (void) second;
        return *this;
    }

    virtual RawBuffer getDER() const {
        return RawBuffer();
    }

    virtual KeyType getType() const {
        return KeyType::KEY_ECDSA_PRIVATE;
    }

};

} // namespace CKM

