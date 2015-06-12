#include <exception.h>
#include <key-provider.h>
#include <dpl/log/log.h>

namespace {

template<typename T>
CKM::RawBuffer toRawBuffer(const T &data)
{
    CKM::RawBuffer output;
    const unsigned char *ptr = reinterpret_cast<const unsigned char*>(&data);
    output.assign(ptr, ptr + sizeof(T));
    return output;
}

// You cannot use toRawBuffer template with pointers
template<typename T>
CKM::RawBuffer toRawBuffer(T *)
{
    class NoPointerAllowed { NoPointerAllowed(){} };
    NoPointerAllowed a;
    return CKM::RawBuffer();
}

} // anonymous namespace

using namespace CKM;

WrappedKeyAndInfoContainer::WrappedKeyAndInfoContainer()
{
    wrappedKeyAndInfo = new WrappedKeyAndInfo;
    memset(wrappedKeyAndInfo, 0, sizeof(WrappedKeyAndInfo));
}

WrappedKeyAndInfoContainer::WrappedKeyAndInfoContainer(const unsigned char *data)
{
    wrappedKeyAndInfo = new WrappedKeyAndInfo;
    memcpy(wrappedKeyAndInfo, data, sizeof(WrappedKeyAndInfo));
}

WrappedKeyAndInfo& WrappedKeyAndInfoContainer::getWrappedKeyAndInfo()
{
    return *wrappedKeyAndInfo;
}

void WrappedKeyAndInfoContainer::setKeyInfoKeyLength(const unsigned int length){
    wrappedKeyAndInfo->keyInfo.keyLength = length;
}

void WrappedKeyAndInfoContainer::setKeyInfoLabel(const std::string label)
{
    strncpy(
        wrappedKeyAndInfo->keyInfo.label,
        label.c_str(),
        MAX_LABEL_SIZE);
}

void WrappedKeyAndInfoContainer::setKeyInfoSalt(const unsigned char *salt, const int size)
{
    memcpy(wrappedKeyAndInfo->keyInfo.salt, salt, size);
}

void WrappedKeyAndInfoContainer::setKeyInfo(const KeyComponentsInfo *keyComponentsInfo)
{
    memcpy(&(wrappedKeyAndInfo->keyInfo), keyComponentsInfo, sizeof(KeyComponentsInfo));
}

WrappedKeyAndInfoContainer::~WrappedKeyAndInfoContainer()
{
    delete wrappedKeyAndInfo;
}

KeyAndInfoContainer::KeyAndInfoContainer()
{
    keyAndInfo = new KeyAndInfo;
    memset(keyAndInfo, 0, sizeof(KeyAndInfo));
}

KeyAndInfoContainer::KeyAndInfoContainer(const unsigned char *data)
{
    keyAndInfo = new KeyAndInfo;
    memcpy(keyAndInfo, data, sizeof(KeyAndInfo));
}

KeyAndInfo& KeyAndInfoContainer::getKeyAndInfo()
{
    return *keyAndInfo;
}

void KeyAndInfoContainer::setKeyInfoKeyLength(unsigned int length)
{
    keyAndInfo->keyInfo.keyLength = length;
}

void KeyAndInfoContainer::setKeyInfo(const KeyComponentsInfo *keyComponentsInfo)
{
    memcpy(&(keyAndInfo->keyInfo), keyComponentsInfo, sizeof(KeyComponentsInfo));
}

KeyAndInfoContainer::~KeyAndInfoContainer()
{
    // overwrite key
    char *ptr = reinterpret_cast<char*>(keyAndInfo);
    memset(ptr, 0, sizeof(KeyAndInfo));
    // verification
    for (size_t size = 0; size < sizeof(KeyAndInfo); ++size) {
        if (ptr[size]) {
            LogError("Write momory error! Memory used by key was not owerwritten.");
        }
    }
    delete keyAndInfo;
}

KeyProvider::KeyProvider()
    : m_kmcDKEK(NULL)
    , m_isInitialized(false)
{
    LogDebug("Created empty KeyProvider");
}

KeyProvider::KeyProvider(
    const RawBuffer &domainKEKInWrapForm,
    const Password &password)
    : m_kmcDKEK(new KeyAndInfoContainer())
    , m_isInitialized(true)
{
    if (!m_isInitialized) {
        ThrowErr(Exc::InternalError, "Object not initialized!. Should not happened");
    }
    if (domainKEKInWrapForm.size() != sizeof(WrappedKeyAndInfo)) {
        LogError("input size:" << domainKEKInWrapForm.size()
            << " Expected: " << sizeof(WrappedKeyAndInfo));
        ThrowErr(Exc::InternalError, "buffer doesn't have proper size to store WrappedKeyAndInfo in KeyProvider Constructor");
    }

    WrappedKeyAndInfoContainer wkmcDKEK = WrappedKeyAndInfoContainer(domainKEKInWrapForm.data());

    char *concat_user_pass = NULL;
    uint8_t PKEK1[MAX_KEY_SIZE];

    concat_user_pass = concat_password_user(
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.label,
        password.c_str());

    if (!PKCS5_PBKDF2_HMAC_SHA1(
        concat_user_pass,
        strlen(concat_user_pass),
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.salt,
        MAX_SALT_SIZE,
        PBKDF2_ITERATIONS,
        MAX_KEY_SIZE,
        PKEK1)) {

        delete[] concat_user_pass;
        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");
    }

    delete[] concat_user_pass;

    int keyLength;

    if (0 > (keyLength = decryptAes256Gcm(
        wkmcDKEK.getWrappedKeyAndInfo().wrappedKey,
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.keyLength,
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.tag,
        PKEK1,
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.iv,
        m_kmcDKEK->getKeyAndInfo().key))) {

        ThrowErr(Exc::AuthenticationFailed, "VerifyDomainKEK failed in KeyProvider Constructor");
    }

    m_kmcDKEK->setKeyInfo(&(wkmcDKEK.getWrappedKeyAndInfo().keyInfo));
    m_kmcDKEK->setKeyInfoKeyLength((unsigned int)keyLength);
}

KeyProvider& KeyProvider::operator=(KeyProvider &&second)
{
    LogDebug("Moving KeyProvider");
    if (this == &second)
        return *this;
    m_isInitialized = second.m_isInitialized;
    m_kmcDKEK = second.m_kmcDKEK;
    second.m_isInitialized = false;
    second.m_kmcDKEK = NULL;
    return *this;
}

KeyProvider::KeyProvider(KeyProvider &&second)
{
    LogDebug("Moving KeyProvider");
    m_isInitialized = second.m_isInitialized;
    m_kmcDKEK = second.m_kmcDKEK;
    second.m_isInitialized = false;
    second.m_kmcDKEK = NULL;
}

bool KeyProvider::isInitialized()
{
    return m_isInitialized;
}

RawBuffer KeyProvider::getPureDomainKEK()
{
    if (!m_isInitialized) {
        ThrowErr(Exc::InternalError, "Object not initialized!");
    }

    // TODO secure
    return RawBuffer(m_kmcDKEK->getKeyAndInfo().key, (m_kmcDKEK->getKeyAndInfo().key) + m_kmcDKEK->getKeyAndInfo().keyInfo.keyLength);
}

RawBuffer KeyProvider::getWrappedDomainKEK(const Password &password)
{
    if (!m_isInitialized) {
        ThrowErr(Exc::InternalError, "Object not initialized!");
    }

    WrappedKeyAndInfoContainer wkmcDKEK = WrappedKeyAndInfoContainer();

    char *concat_user_pass = NULL;
    uint8_t PKEK1[MAX_KEY_SIZE];

    concat_user_pass = concat_password_user(
        m_kmcDKEK->getKeyAndInfo().keyInfo.label,
        password.c_str());

    if (!PKCS5_PBKDF2_HMAC_SHA1(
        concat_user_pass,
        strlen(concat_user_pass),
        m_kmcDKEK->getKeyAndInfo().keyInfo.salt,
        MAX_SALT_SIZE,
        PBKDF2_ITERATIONS,
        MAX_KEY_SIZE,
        PKEK1)) {

        delete[] concat_user_pass;
        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");
    }

    delete[] concat_user_pass;

    wkmcDKEK.setKeyInfo(&(m_kmcDKEK->getKeyAndInfo().keyInfo));

    int wrappedKeyLength;

    if (0 > (wrappedKeyLength = encryptAes256Gcm(
        m_kmcDKEK->getKeyAndInfo().key,
        m_kmcDKEK->getKeyAndInfo().keyInfo.keyLength,
        PKEK1,
        m_kmcDKEK->getKeyAndInfo().keyInfo.iv,
        wkmcDKEK.getWrappedKeyAndInfo().wrappedKey,
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.tag))) {

        ThrowErr(Exc::InternalError, "WrapDKEK Failed in KeyProvider::getDomainKEK");
    }

    wkmcDKEK.setKeyInfoKeyLength((unsigned int)wrappedKeyLength);

    LogDebug("getDomainKEK(password) Success");
    return toRawBuffer(wkmcDKEK.getWrappedKeyAndInfo());
}


RawBuffer KeyProvider::getPureDEK(const RawBuffer &DEKInWrapForm)
{
    if (!m_isInitialized) {
        ThrowErr(Exc::InternalError, "Object not initialized!");
    }

    if (DEKInWrapForm.size() != sizeof(WrappedKeyAndInfo)){
        LogError("input size:" << DEKInWrapForm.size()
                  << " Expected: " << sizeof(WrappedKeyAndInfo));
        ThrowErr(Exc::InternalError,
                "buffer doesn't have proper size to store "
                "WrappedKeyAndInfo in KeyProvider::getPureDEK");
    }

    KeyAndInfoContainer kmcDEK = KeyAndInfoContainer();
    WrappedKeyAndInfoContainer wkmcDEK = WrappedKeyAndInfoContainer(DEKInWrapForm.data());

    uint8_t PKEK2[MAX_KEY_SIZE];
    int keyLength;

    if (!PKCS5_PBKDF2_HMAC_SHA1(
        wkmcDEK.getWrappedKeyAndInfo().keyInfo.label,
        strlen(wkmcDEK.getWrappedKeyAndInfo().keyInfo.label),
        m_kmcDKEK->getKeyAndInfo().key,
        MAX_SALT_SIZE,
        PBKDF2_ITERATIONS,
        MAX_KEY_SIZE,
        PKEK2)) {

        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");
    }

    if (0 > (keyLength = decryptAes256Gcm(
        wkmcDEK.getWrappedKeyAndInfo().wrappedKey,
        wkmcDEK.getWrappedKeyAndInfo().keyInfo.keyLength,
        wkmcDEK.getWrappedKeyAndInfo().keyInfo.tag,
        PKEK2,
        wkmcDEK.getWrappedKeyAndInfo().keyInfo.iv,
        kmcDEK.getKeyAndInfo().key))) {

        ThrowErr(Exc::InternalError,
            "UnwrapDEK Failed in KeyProvider::getPureDEK");
    }

    kmcDEK.setKeyInfoKeyLength((unsigned int)keyLength);

    LogDebug("getPureDEK SUCCESS");
    return RawBuffer(
        kmcDEK.getKeyAndInfo().key,
        (kmcDEK.getKeyAndInfo().key) + kmcDEK.getKeyAndInfo().keyInfo.keyLength);
}

RawBuffer KeyProvider::generateDEK(const std::string &smackLabel)
{
    if (!m_isInitialized) {
        ThrowErr(Exc::InternalError, "Object not initialized!");
    }

    WrappedKeyAndInfoContainer wkmcDEK = WrappedKeyAndInfoContainer();
    std::string resized_smackLabel;

    if (smackLabel.length() < APP_LABEL_SIZE)
        resized_smackLabel = smackLabel;
    else
        resized_smackLabel = smackLabel.substr(0, APP_LABEL_SIZE-1);

    uint8_t key[MAX_KEY_SIZE], PKEK2[MAX_KEY_SIZE];

    if (!RAND_bytes(key, m_kmcDKEK->getKeyAndInfo().keyInfo.keyLength) ||
        !RAND_bytes(wkmcDEK.getWrappedKeyAndInfo().keyInfo.iv, MAX_IV_SIZE)) {

        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");
    }

    if (!PKCS5_PBKDF2_HMAC_SHA1(
        resized_smackLabel.c_str(),
        strlen(resized_smackLabel.c_str()),
        m_kmcDKEK->getKeyAndInfo().key,
        MAX_SALT_SIZE,
        PBKDF2_ITERATIONS,
        MAX_KEY_SIZE,
        PKEK2)) {

        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");
    }

    int wrappedKeyLength;

    if (0 > (wrappedKeyLength = encryptAes256Gcm(
        key,
        m_kmcDKEK->getKeyAndInfo().keyInfo.keyLength,
        PKEK2,
        wkmcDEK.getWrappedKeyAndInfo().keyInfo.iv,
        wkmcDEK.getWrappedKeyAndInfo().wrappedKey,
        wkmcDEK.getWrappedKeyAndInfo().keyInfo.tag))) {

        ThrowErr(Exc::InternalError, "GenerateDEK Failed in KeyProvider::generateDEK");
    }

    wkmcDEK.setKeyInfoKeyLength((unsigned int)wrappedKeyLength);
    wkmcDEK.setKeyInfoSalt(m_kmcDKEK->getKeyAndInfo().key, MAX_SALT_SIZE);
    wkmcDEK.setKeyInfoLabel(resized_smackLabel);

    LogDebug("GenerateDEK Success");
    return toRawBuffer(wkmcDEK.getWrappedKeyAndInfo());
}

RawBuffer KeyProvider::reencrypt(
    const RawBuffer &domainKEKInWrapForm,
    const Password &oldPass,
    const Password &newPass)
{
    if (domainKEKInWrapForm.size() != sizeof(WrappedKeyAndInfo)) {
        LogError("input size:" << domainKEKInWrapForm.size()
                  << " Expected: " << sizeof(WrappedKeyAndInfo));
        ThrowErr(Exc::InternalError,
                "buffer doesn't have proper size to store "
                "WrappedKeyAndInfo in KeyProvider::reencrypt");
    }

    WrappedKeyAndInfoContainer wkmcOldDKEK = WrappedKeyAndInfoContainer(domainKEKInWrapForm.data());
    WrappedKeyAndInfoContainer wkmcNewDKEK = WrappedKeyAndInfoContainer();
    KeyAndInfoContainer kmcDKEK = KeyAndInfoContainer();

    char *concat_user_pass = NULL;
    uint8_t PKEK1[MAX_KEY_SIZE];
    int keyLength = 0;


    concat_user_pass = concat_password_user(
        wkmcOldDKEK.getWrappedKeyAndInfo().keyInfo.label,
        oldPass.c_str());

    if (!PKCS5_PBKDF2_HMAC_SHA1(
        concat_user_pass,
        strlen(concat_user_pass),
        wkmcOldDKEK.getWrappedKeyAndInfo().keyInfo.salt,
        MAX_SALT_SIZE,
        PBKDF2_ITERATIONS,
        MAX_KEY_SIZE,
        PKEK1)) {

        delete[] concat_user_pass;
        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");
    }
    delete[] concat_user_pass;

    if (0 > (keyLength = decryptAes256Gcm(
        wkmcOldDKEK.getWrappedKeyAndInfo().wrappedKey,
        wkmcOldDKEK.getWrappedKeyAndInfo().keyInfo.keyLength,
        wkmcOldDKEK.getWrappedKeyAndInfo().keyInfo.tag,
        PKEK1,
        wkmcOldDKEK.getWrappedKeyAndInfo().keyInfo.iv,
        kmcDKEK.getKeyAndInfo().key))) {

        ThrowErr(Exc::AuthenticationFailed, "Incorrect Old Password ");
    }

    kmcDKEK.setKeyInfo(&(wkmcOldDKEK.getWrappedKeyAndInfo().keyInfo));
    kmcDKEK.setKeyInfoKeyLength((unsigned int)keyLength);

    concat_user_pass = concat_password_user(
        kmcDKEK.getKeyAndInfo().keyInfo.label,
        newPass.c_str());

    if (!PKCS5_PBKDF2_HMAC_SHA1(
        concat_user_pass,
        strlen(concat_user_pass),
        kmcDKEK.getKeyAndInfo().keyInfo.salt,
        MAX_SALT_SIZE,
        PBKDF2_ITERATIONS,
        MAX_KEY_SIZE,
        PKEK1)) {

        delete[] concat_user_pass;
        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");
    }

    delete[] concat_user_pass;

    int wrappedKeyLength = 0;
    wkmcNewDKEK.setKeyInfo(&(kmcDKEK.getKeyAndInfo().keyInfo));

    if (0 > (wrappedKeyLength = encryptAes256Gcm(
        kmcDKEK.getKeyAndInfo().key,
        kmcDKEK.getKeyAndInfo().keyInfo.keyLength,
        PKEK1,
        kmcDKEK.getKeyAndInfo().keyInfo.iv,
        wkmcNewDKEK.getWrappedKeyAndInfo().wrappedKey,
        wkmcNewDKEK.getWrappedKeyAndInfo().keyInfo.tag))) {

        ThrowErr(Exc::InternalError, "UpdateDomainKEK in KeyProvider::reencrypt Failed");
    }

    wkmcNewDKEK.setKeyInfoKeyLength((unsigned int)wrappedKeyLength);

    LogDebug("reencrypt SUCCESS");
    return toRawBuffer(wkmcNewDKEK.getWrappedKeyAndInfo());
}


RawBuffer KeyProvider::generateDomainKEK(
    const std::string &user,
    const Password &userPassword)
{
    WrappedKeyAndInfoContainer wkmcDKEK = WrappedKeyAndInfoContainer();
    uint8_t key[MAX_KEY_SIZE], PKEK1[MAX_KEY_SIZE];

    if (!RAND_bytes(wkmcDKEK.getWrappedKeyAndInfo().keyInfo.salt, MAX_SALT_SIZE) ||
        !RAND_bytes(key, MAX_KEY_SIZE) ||
        !RAND_bytes(wkmcDKEK.getWrappedKeyAndInfo().keyInfo.iv, MAX_IV_SIZE))
        ThrowErr(Exc::InternalError, "OPENSSL_ENGINE_ERROR");

    int wrappedKeyLength;
    char *concat_user_pass = NULL;
    concat_user_pass = concat_password_user(user.c_str(), userPassword.c_str());
    if (!PKCS5_PBKDF2_HMAC_SHA1(
        concat_user_pass,
        strlen(concat_user_pass),
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.salt,
        MAX_SALT_SIZE,
        PBKDF2_ITERATIONS,
        MAX_KEY_SIZE,
        PKEK1)) {

        delete[] concat_user_pass;
        ThrowErr(Exc::InternalError, "OPENSSL_ENGINED_ERROR");
    }

    delete[] concat_user_pass;

    if (0 > (wrappedKeyLength = encryptAes256Gcm(
        key,
        MAX_KEY_SIZE,
        PKEK1,
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.iv,
        wkmcDKEK.getWrappedKeyAndInfo().wrappedKey,
        wkmcDKEK.getWrappedKeyAndInfo().keyInfo.tag))) {

        ThrowErr(Exc::InternalError,
            "GenerateDomainKEK Failed in KeyProvider::generateDomainKEK");
    }

    wkmcDKEK.setKeyInfoKeyLength((unsigned int)wrappedKeyLength);
    wkmcDKEK.setKeyInfoLabel(user);

    LogDebug("generateDomainKEK Success");
    return toRawBuffer(wkmcDKEK.getWrappedKeyAndInfo());
}

int KeyProvider::initializeLibrary()
{
    LogDebug("initializeLibrary Success");
    return SUCCESS;
}

int KeyProvider::closeLibrary()
{
    LogDebug("closeLibrary Success");
    return SUCCESS;
}

KeyProvider::~KeyProvider()
{
    LogDebug("KeyProvider Destructor");
}

int KeyProvider::encryptAes256Gcm(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag)
{

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MAX_IV_SIZE, NULL)) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        return OPENSSL_ENGINE_ERROR;
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        return OPENSSL_ENGINE_ERROR;
    }
    ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAX_IV_SIZE, tag)) {
        return OPENSSL_ENGINE_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int KeyProvider::decryptAes256Gcm(const unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext)
{

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return OPENSSL_ENGINE_ERROR;
    }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MAX_IV_SIZE, NULL)) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MAX_IV_SIZE, tag)) {
        return OPENSSL_ENGINE_ERROR;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        return OPENSSL_ENGINE_ERROR;
    }
    plaintext_len = len;

    if (!(ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len))) {
        return OPENSSL_ENGINE_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }
    else {
        return -1;
    }
}

char * KeyProvider::concat_password_user(const char *user, const char *password)
{
    char *concat_user_pass = NULL;
    char *resized_user = NULL;
    int concat_user_pass_len = 0;

    if (strlen(user) > MAX_LABEL_SIZE-1) {
        resized_user = new char[MAX_LABEL_SIZE];
        memcpy(resized_user, user, MAX_LABEL_SIZE-1);
        resized_user[MAX_LABEL_SIZE-1] = '\0';
    }
    else {
        resized_user = new char[strlen(user)+1];
        memcpy(resized_user, user, strlen(user));
        resized_user[strlen(user)] = '\0';
    }
    concat_user_pass_len = strlen(resized_user) + strlen(password) + 1;
    concat_user_pass = new char[concat_user_pass_len];

    memset(concat_user_pass, '\0', concat_user_pass_len);
    memcpy(concat_user_pass, password, strlen(password));
    memcpy(&(concat_user_pass[strlen(password)]), resized_user, strlen(resized_user));
    concat_user_pass[strlen(resized_user) + strlen(password)] = '\0';

    delete[] resized_user;
    return concat_user_pass;
}
