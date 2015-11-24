#pragma once

#include <string.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <memory>

#include <ckm/ckm-type.h>

#ifndef SUCCESS
#define SUCCESS               0
#endif
#ifndef ERROR
#define ERROR                -1
#endif
#ifndef INVALID_ARGUMENTS
#define INVALID_ARGUMENTS    -2
#endif
#ifndef VERIFY_DATA_ERROR
#define VERIFY_DATA_ERROR    -3
#endif
#ifndef OPENSSL_ENGINE_ERROR
#define OPENSSL_ENGINE_ERROR -4
#endif
#ifndef UNKNOWN_ERROR
#define UNKNOWN_ERROR        -5
#endif

#define AES256_KEY_LEN_BITS   256
#define AES256_KEY_LEN_BYTSE  (AES256_KEY_LEN_BITS / 8)
// Unused
//#define AES_GCM_TAG_SIZE      32

#define PBKDF2_SALT_LEN       16
#define PBKDF2_ITERATIONS     4096

#define MAX_IV_SIZE           16
#define MAX_SALT_SIZE         16
#define MAX_KEY_SIZE          32
#define MAX_WRAPPED_KEY_SIZE  32
#define MAX_LABEL_SIZE        32
#define DOMAIN_NAME_SIZE      32
#define APP_LABEL_SIZE        32

namespace CKM {

typedef struct KeyComponentsInfo_ {
    uint32_t keyLength;
    char label[MAX_LABEL_SIZE];
    uint8_t salt[MAX_SALT_SIZE];
    uint8_t iv[MAX_IV_SIZE];
    uint8_t tag[MAX_IV_SIZE];
} KeyComponentsInfo;

typedef struct KeyAndInfo_ {
    KeyComponentsInfo keyInfo;
    uint8_t key[MAX_KEY_SIZE];
} KeyAndInfo;

typedef struct WrappedKeyAndInfo_ {
    KeyComponentsInfo keyInfo;
    uint8_t wrappedKey[MAX_WRAPPED_KEY_SIZE];
} WrappedKeyAndInfo;

class WrappedKeyAndInfoContainer{
public:
    WrappedKeyAndInfoContainer();
    WrappedKeyAndInfoContainer(const unsigned char*);
    WrappedKeyAndInfo& getWrappedKeyAndInfo();
    void setKeyInfoKeyLength(const unsigned int);
    void setKeyInfoLabel(const std::string);
    void setKeyInfoSalt(const unsigned char*, const int);
    void setKeyInfo(const KeyComponentsInfo*);
    ~WrappedKeyAndInfoContainer();
private:
    WrappedKeyAndInfo *wrappedKeyAndInfo;
};

class KeyAndInfoContainer{
public:
    KeyAndInfoContainer();
    KeyAndInfoContainer(const unsigned char*);
    KeyAndInfo& getKeyAndInfo();
    void setKeyInfoKeyLength(const unsigned int);
    void setKeyInfo(const KeyComponentsInfo*);
    ~KeyAndInfoContainer();
private:
    KeyAndInfo *keyAndInfo;
};


// This is internal api so all functions should throw exception on errors.
class KeyProvider {
public:
    // To store in std containers
    KeyProvider();
    // In constructor you must check if SKMM is initialized. On error -> exception
    // keyInWrapForm should be used like this:
    // if (keyInWrapForm.size() != sizeof(WrappedKeyAndInfo))
    //     throw exception; // buffer does not have proper size to store WrappedKeyAndInfo
    // WrappedKeyAndInfo *wkm = static_cast<WrappedKeyAndInfo>(keyInWrapForm.data());
    KeyProvider(const RawBuffer &domainKEKInWrapForm, const Password &password);

    KeyProvider(KeyProvider &&);
    KeyProvider(const KeyProvider &) = delete;
    KeyProvider& operator=(const KeyProvider &) = delete;
    KeyProvider& operator=(KeyProvider &&);

    bool isInitialized();

    // Returns Key used to decrypt database.
    RawBuffer getPureDomainKEK();

    // Returns Key in form used to store key in file
    // Requied by Control::resetPassword(const RawBuffer &newPassword);
    // This api should be used only on Tizen 2.2.1
    RawBuffer getWrappedDomainKEK(const Password &password);

    // EncryptedKey key extracted from database. Used to encrypt application data.
    // This key will be used to decrypt/encrypt data in ROW
    RawBuffer getPureDEK(const RawBuffer &DEKInWrapForm);

    // Returns WRAPPED DEK. This will be written to datbase.
    // This key will be used to encrypt all application information.
    // All application are identified by smackLabel.
    RawBuffer generateDEK(const std::string &smackLabel);

    // used by change user password. On error -> exception
    static RawBuffer reencrypt(
        const RawBuffer &domainKEKInWrapForm,
        const Password &oldPass,
        const Password &newPass);

    // First run of application for some user. DomainKEK was not created yet. We must create one.
    // This key will be used to encrypt user database.
    static RawBuffer generateDomainKEK(const std::string &user, const Password &userPassword);

    // This will be called by framework at the begin of the program
    static int initializeLibrary();
    // This will be called by framework at the end of the program
    static int closeLibrary();

    virtual ~KeyProvider();
private:
    // KeyAndInfoContainer class
    std::shared_ptr<KeyAndInfoContainer> m_kmcDKEK;
    bool m_isInitialized;

    static int encryptAes256Gcm(
        const unsigned char *plaintext,
        int plaintext_len,
        const unsigned char *key,
        const unsigned char *iv,
        unsigned char *ciphertext,
        unsigned char *tag);

    static int decryptAes256Gcm(
        const unsigned char *ciphertext,
        int ciphertext_len,
        unsigned char *tag,
        const unsigned char *key,
        const unsigned char *iv,
        unsigned char *plaintext);

    static char * concat_password_user(
        const char *user,
        const char *password);

};

} // namespace CKM
