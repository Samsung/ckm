
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <dpl/log/log.h>
#include <base64.h>
#include <ckm/ckm-error.h>

#include <DBCryptoModule.h>

namespace CKM {

DBCryptoModule::DBCryptoModule(){}

DBCryptoModule::DBCryptoModule(DBCryptoModule &&second) {
    m_domainKEK = std::move(second.m_domainKEK);
    m_keyMap = std::move(second.m_keyMap);
}

DBCryptoModule& DBCryptoModule::operator=(DBCryptoModule &&second) {
    if (this == &second)
        return *this;
    m_domainKEK = std::move(second.m_domainKEK);
    m_keyMap = std::move(second.m_keyMap);
    return *this;
}

DBCryptoModule::DBCryptoModule(RawBuffer &domainKEK)
{
    m_domainKEK = domainKEK;
}

bool DBCryptoModule::haveKey(const std::string &smackLabel)
{
    return (m_keyMap.count(smackLabel) > 0);
}

int DBCryptoModule::pushKey(const std::string &smackLabel,
                            const RawBuffer &applicationKey)
{
    if (m_domainKEK.size() == 0) {
        ThrowMsg(Exception::DomainKeyError, "Empty domain key.");
    }
    if (smackLabel.length() == 0) {
        ThrowMsg(Exception::SmackLabelError, "Empty smack label.");
    }
    if (applicationKey.size() == 0) {
        ThrowMsg(Exception::AppKeyError, "Empty application key.");
    }
    if (haveKey(smackLabel)) {
        ThrowMsg(Exception::AppKeyError, "Application key for " << smackLabel
                 << "label already exists.");
    }
    m_keyMap[smackLabel] = applicationKey;
    return KEY_MANAGER_API_SUCCESS;
}

std::size_t DBCryptoModule::insertDigest(RawBuffer &data, const int dataSize)
{
    RawBuffer digest;

    try {
        digest = digestData(data, dataSize);
    } catch (Exception::Base &e) {
        LogError("Failed to calculate digest in insertDigest: " <<
                 e.DumpToString());
        throw;
    }
    if (SHA_DIGEST_LENGTH != digest.size()) {
        ThrowMsg(Exception::DigestError, "Cannot insert digest: size mismatch.");
    }
    data.insert(data.begin(), digest.begin(), digest.end());
    return digest.size();
}

void DBCryptoModule::removeDigest(RawBuffer &data, RawBuffer &digest)
{
    if (data.size() < SHA_DIGEST_LENGTH) {
        ThrowMsg(Exception::DigestError, "Cannot remove digest: data size "
                 "mismatch.");
    }

    digest.assign(data.begin(), data.begin() + SHA_DIGEST_LENGTH);
    data.erase(data.begin(), data.begin() + SHA_DIGEST_LENGTH);
}

int DBCryptoModule::encryptRow(const std::string &password, DBRow &row)
{
    RawBuffer emptyiv;
    DBRow crow = row;
    std::size_t dlen;
    RawBuffer userkey;
    RawBuffer appkey;

    crow.algorithmType = DBCMAlgType::NONE;
    if (m_domainKEK.size() == 0) {
        ThrowMsg(Exception::DomainKeyError, "Empty domain key.");
    }
    if (row.dataSize <= 0) {
        ThrowMsg(Exception::EncryptDBRowError, "Invalid dataSize.");
    }
    if (!haveKey(row.smackLabel)) {
        ThrowMsg(Exception::EncryptDBRowError, "Missing application key for " <<
                 row.smackLabel << " label.");
    }
    appkey = m_keyMap[row.smackLabel];
    crow.encryptionScheme = 0;

    try {
        dlen = insertDigest(crow.data, crow.dataSize);
        cryptAES(crow.data, crow.dataSize + dlen, appkey, emptyiv);
        crow.encryptionScheme |= ENCR_APPKEY;
        if (!password.empty()) {
            generateKeysFromPassword(password, userkey, crow.iv);
            cryptAES(crow.data, 0, userkey, crow.iv);
            crow.encryptionScheme |= ENCR_PASSWORD;
        }
        encBase64(crow.data);
        crow.encryptionScheme |= ENCR_BASE64;
        encBase64(crow.iv);
    } catch (Exception::Base &e) {
        LogError("Failed to encrypt db row: " << e.DumpToString());
        throw;
    }
    crow.algorithmType = DBCMAlgType::AES_CBC_256;
    row = crow;

    return KEY_MANAGER_API_SUCCESS;
}

int DBCryptoModule::decryptRow(const std::string &password, DBRow &row)
{
    DBRow crow = row;
    RawBuffer appkey;
    RawBuffer userkey;
    RawBuffer dropiv;
    RawBuffer emptyiv;
    RawBuffer digest, dataDigest;

    if (m_domainKEK.size() == 0) {
        ThrowMsg(Exception::DomainKeyError, "Empty domain key.");
    }
    if (row.dataSize <= 0) {
        ThrowMsg(Exception::DecryptDBRowError, "Invalid dataSize.");
    }
    if (row.algorithmType != DBCMAlgType::AES_CBC_256) {
        ThrowMsg(Exception::DecryptDBRowError, "Invalid algorithm type.");
    }
    if (row.encryptionScheme & ENCR_PASSWORD)
        if (password.empty()) {
            ThrowMsg(Exception::DecryptDBRowError,
                     "DB row is password protected, but given password is "
                     "empty.");
        }
    if (!haveKey(row.smackLabel)) {
        ThrowMsg(Exception::DecryptDBRowError, "Missing application key for " <<
                 row.smackLabel << " label.");
    }
    appkey = m_keyMap[row.smackLabel];

    try {
        decBase64(crow.iv);
        if (crow.encryptionScheme & ENCR_BASE64) {
            decBase64(crow.data);
        }
        if (crow.encryptionScheme & ENCR_PASSWORD) {
            generateKeysFromPassword(password, userkey, dropiv);
            decryptAES(crow.data, 0, userkey, crow.iv);
        }
        if (crow.encryptionScheme & ENCR_APPKEY) {
            decryptAES(crow.data, 0, appkey, emptyiv);
        }
        removeDigest(crow.data, digest);
        if (static_cast<std::size_t>(crow.dataSize) != crow.data.size()) {
            ThrowMsg(Exception::DecryptDBRowError,
                     "Decrypted db row data size mismatch.");
        }
        dataDigest = digestData(crow.data, 0);
    } catch (Exception::Base &e) {
        LogError("Failed to decrypt db row: " << e.DumpToString());
        throw;
    }
    if (not equalDigests(digest, dataDigest)) {
        ThrowMsg(Exception::DecryptDBRowError,
                 "Decrypted db row data digest mismatch.");
    }
    row = crow;

    return KEY_MANAGER_API_SUCCESS;
}

RawBuffer DBCryptoModule::generateRandIV(void)
{
    int ret = -1;
    RawBuffer civ(EVP_MAX_IV_LENGTH);

    ret = RAND_bytes(civ.data(), civ.size());
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLError, "RAND_bytes failed");
    }
    return civ;
}

void DBCryptoModule::generateKeysFromPassword(const std::string &password,
                                              RawBuffer &key, RawBuffer &iv)
{
    int ret = -1;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned int keyLen = EVP_CIPHER_key_length(cipher);
    unsigned int ivLen = EVP_CIPHER_iv_length(cipher);
#if 0
    const EVP_MD *md = EVP_sha1();
#endif

    if (password.empty()) {
        ThrowMsg(Exception::KeyGenerationError, "Password is empty.");
    }
    key.resize(keyLen);
    iv.resize(ivLen);
    iv = generateRandIV();
    ret = PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(),
            NULL, 0, 1024, keyLen, key.data());
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLError, "PKCS5_PBKDF2_HMAC_SHA1 has failed.");
    }
#if 0
    ret = EVP_BytesToKey(cipher, md, NULL,
                         const_cast<const unsigned char *>(&password[0]),
                         strlen(reinterpret_cast<const char *>(&password[0])),
                         1, &key[0], &iv[0]);
    LogDebug("Generated key len: " << ret);
    if (ret > 0)
        ret = EXIT_SUCCESS;
#endif
}

void DBCryptoModule::cryptAES(RawBuffer &data, std::size_t len,
                              const RawBuffer &key, const RawBuffer &iv)
{
    int ret = -1;
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    std::size_t keyLen = EVP_CIPHER_key_length(cipher);
    std::size_t ivLen = EVP_CIPHER_iv_length(cipher);
    int maxBufLen;
    int outl, outlf;

    if (keyLen == 0) {
        ThrowMsg(Exception::OpenSSLEncryptError, "Got invalid key length for "
                 "our cipher from openssl.");
    }
    if (key.size() != keyLen) {
        ThrowMsg(Exception::AESEncryptionError, "Wrong key size.");
    }
    if (data.size() == 0) {
        ThrowMsg(Exception::AESEncryptionError, "Empty data.");
    }
    /* iv may be empty */
    if (iv.size() > 0)
        if (iv.size() != ivLen) {
            ThrowMsg(Exception::AESEncryptionError, "IV size mismatch.");
        }
    if (0 == len)
        len = data.size();
    maxBufLen = len + EVP_CIPHER_block_size(cipher);

    LogDebug("key len: " << keyLen);
    LogDebug("iv len: " << ivLen);
    LogDebug("buf len: " << maxBufLen);
    LogDebug("len: " << len);

    RawBuffer buf(maxBufLen);

    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_EncryptInit_ex(&ctx, cipher, NULL, &key[0], &iv[0]);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLEncryptError, "Failed to initialize "
                 "encryption in openssl.");
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 1);
    ret = EVP_EncryptUpdate(&ctx, &buf[0], &outl, &data[0], len);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLEncryptError, "Failed to encrypt data in "
                 "openssl");
    }
    ret = EVP_EncryptFinal_ex(&ctx, &buf[outl], &outlf);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLEncryptError, "Failed to encrypt data in "
                 "openssl (final)");
    }
    LogDebug("Total out len: " << outl + outlf);
    EVP_CIPHER_CTX_cleanup(&ctx);
    data.assign(buf.begin(), buf.begin() + outl + outlf);
}

void DBCryptoModule::decryptAES(RawBuffer &data, std::size_t len,
                                const RawBuffer &key, const RawBuffer &iv)
{
    int ret = -1;
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    std::size_t keyLen = EVP_CIPHER_key_length(cipher);
    std::size_t ivLen = EVP_CIPHER_iv_length(cipher);
    int maxBufLen;
    int outl, outlf;

    if (keyLen == 0) {
        ThrowMsg(Exception::OpenSSLDecryptError, "Got invalid key length for "
                 "our cipher from openssl.");
    }
    if (key.size() != keyLen) {
        ThrowMsg(Exception::AESDecryptionError, "Wrong key size.");
    }
    if (iv.size() > 0)
        if (iv.size() != ivLen) {
            ThrowMsg(Exception::AESDecryptionError, "Wrong IV size.");
        }
    if (0 == len)
        len = data.size();

    maxBufLen = len + EVP_CIPHER_block_size(cipher) + 1;

    LogDebug("buf len: " << maxBufLen);
    LogDebug("data len: " << len);

    RawBuffer buf(maxBufLen, 0);

    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_DecryptInit_ex(&ctx, cipher, NULL, &key[0], &iv[0]);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLDecryptError, "Failed to initialize "
                 "decryption in openssl.");
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 1);
    ret = EVP_DecryptUpdate(&ctx, &buf[0], &outl, &data[0], len);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLDecryptError, "Failed to decrypt data in "
                 "openssl");
    }
    ret = EVP_DecryptFinal_ex(&ctx, &buf[outl], &outlf);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLDecryptError, "Failed to decrypt data in "
                 "openssl (final)");
    }
    LogDebug("Total out len: " << outl + outlf);
    EVP_CIPHER_CTX_cleanup(&ctx);
    if ((outl + outlf) == 0) {
        ThrowMsg(Exception::OpenSSLDecryptError, "Failed to decrypt data in "
                 "openssl - zero output length (wrong input data?)");
    }
    data.assign(buf.begin(), buf.begin() + outl + outlf);
}

RawBuffer DBCryptoModule::digestData(const RawBuffer &data, std::size_t len)
{
    int ret = -1;
    EVP_MD_CTX ctx;
    const EVP_MD *md = EVP_sha1();
    unsigned int dlen;

    if (data.size() == 0) {
        ThrowMsg(Exception::DigestError, "Empty data.");
    }
    if (0 == len)
        len = data.size();

    ret = EVP_DigestInit(&ctx, md);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLDigestError, "Failed to initialize digest "
                 "in openssl.");
    }
    ret = EVP_DigestUpdate(&ctx, &data[0], len);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLDigestError, "Failed in digest calculation "
                 "in openssl.");
    }
    RawBuffer digest(EVP_MAX_MD_SIZE);
    ret = EVP_DigestFinal(&ctx, &digest[0], &dlen);
    if (ret != 1) {
        ThrowMsg(Exception::OpenSSLDigestError, "Failed in digest final "
                 "calculation in openssl.");
    }
    if (dlen != EVP_MAX_MD_SIZE)
        digest.resize(dlen);
    return digest;
}

void DBCryptoModule::encBase64(RawBuffer &data)
{
    Base64Encoder benc;
    RawBuffer encdata;

    try {
        benc.append(data);
        benc.finalize();
        encdata = benc.get();
    } catch (Base64Encoder::Exception::Base &e) {
        LogError("Failed to encode data in Base64Encoder: " <<
                 e.DumpToString());
        throw;
    }

    if (encdata.size() == 0) {
        ThrowMsg(Exception::Base64EncoderError, "Base64Encoder returned empty data.");
    }

    data = std::move(encdata);
}

void DBCryptoModule::decBase64(RawBuffer &data)
{
    Base64Decoder bdec;
    RawBuffer decdata;

    try {
        bdec.reset();
        bdec.append(data);
        if (not bdec.finalize()) {
            ThrowMsg(Exception::Base64DecoderError,
                     "Failed in Base64Decoder.finalize.");
        }

        decdata = bdec.get();
    } catch (Base64Decoder::Exception::Base &e) {
        LogError("Failed to decode data in Base64Decoder: " <<
                 e.DumpToString());
        throw;
    }
    if (decdata.size() == 0) {
        ThrowMsg(Exception::Base64DecoderError, "Base64Decoder returned empty data.");
    }

    data = std::move(decdata);
}

bool DBCryptoModule::equalDigests(RawBuffer &dig1, RawBuffer &dig2)
{
    if ((dig1.size() != SHA_DIGEST_LENGTH) ||
        (dig2.size() != SHA_DIGEST_LENGTH))
        return false;
    return (dig1 == dig2);
}

} // namespace CKM

