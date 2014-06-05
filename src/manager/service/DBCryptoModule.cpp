
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

#include <DBCryptoModule.h>

namespace CKM {

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
    int ret = -1;

    if (m_domainKEK.size() == 0)
        return ret;
    if (smackLabel.length() == 0)
        return ret;
    if (applicationKey.size() == 0)
        return ret;
    if (haveKey(smackLabel))
        return ret;
    RawBuffer appkey = applicationKey;
    RawBuffer emptyiv;
    if ((ret = decryptAES(appkey, 0, m_domainKEK, emptyiv)))
        return ret;
    m_keyMap[smackLabel] = appkey;

    return EXIT_SUCCESS;
}

int DBCryptoModule::insertDigest(RawBuffer &data, const int dataSize)
{
    int ret = -1;
    RawBuffer digest;

    ret = digestData(data, dataSize, digest);
    if (ret != 0)
        return -1;
    if (SHA_DIGEST_LENGTH != digest.size())
        return -1;
    data.insert(data.begin(), digest.begin(), digest.end());
    ret = digest.size();

    return ret;
}

int DBCryptoModule::removeDigest(RawBuffer &data, RawBuffer &digest)
{
    if (data.size() < SHA_DIGEST_LENGTH)
        return -1;

    int len = data.size();
    digest.assign(data.begin(), data.begin() + SHA_DIGEST_LENGTH);
    digest.resize(SHA_DIGEST_LENGTH);
    data.erase(data.begin(), data.begin() + SHA_DIGEST_LENGTH);
    data.resize(len - SHA_DIGEST_LENGTH);

    return EXIT_SUCCESS;
}

int DBCryptoModule::encryptRow(const RawBuffer &password, DBRow &row)
{
    int ret = -1;
    RawBuffer emptyiv;
    DBRow crow = row;
    int dlen;
    RawBuffer userkey;
    RawBuffer appkey;

    if (m_domainKEK.size() == 0)
        return ret;
    if (row.dataSize <= 0)
        return ret;
    if (!haveKey(row.smackLabel))
        return ret;
    appkey = m_keyMap[row.smackLabel];
    crow.encryptionScheme = 0;

    dlen = insertDigest(crow.data, crow.dataSize);
    if (dlen <= 0)
        return ret;
    ret = cryptAES(crow.data, crow.dataSize + dlen, appkey, emptyiv);
    if (ret != 0)
        return ret;
    crow.encryptionScheme |= DBRow::ENCR_APPKEY;
    if (password.size() > 0) {
        if ((ret = generateKeysFromPassword(password, userkey, crow.iv)))
            return ret;
        ret = cryptAES(crow.data, 0, userkey, crow.iv);
        if (ret != 0)
            return ret;
        crow.encryptionScheme |= DBRow::ENCR_PASSWORD;
    }
    ret = encBase64(crow.data);
    if (ret != 0)
        return ret;
    crow.encryptionScheme |= DBRow::ENCR_BASE64;
    ret = encBase64(crow.iv);
    if (ret != 0)
        return ret;
    /* TODO: Add setting of algorithmType */
    row = crow;

    return ret;
}

int DBCryptoModule::decryptRow(const RawBuffer &password, DBRow &row)
{
    int ret = -1;
    DBRow crow = row;
    RawBuffer appkey;
    RawBuffer userkey;
    RawBuffer dropiv;
    RawBuffer emptyiv;
    RawBuffer digest, dataDigest;

    if (m_domainKEK.size() == 0)
        return ret;
    if (row.dataSize <= 0)
        return ret;
    if (row.encryptionScheme && DBRow::ENCR_PASSWORD)
        if (password.size() == 0)
            return ret;
    if (!haveKey(row.smackLabel))
        return ret;
    appkey = m_keyMap[row.smackLabel];

    ret = decBase64(crow.iv);
    if (ret)
        return ret;
    if (crow.encryptionScheme && DBRow::ENCR_BASE64) {
        ret = decBase64(crow.data);
        if (ret)
            return ret;
    }
    if (crow.encryptionScheme && DBRow::ENCR_PASSWORD) {
        if ((ret = generateKeysFromPassword(password, userkey, dropiv)))
            return ret;
        ret = decryptAES(crow.data, 0, userkey, crow.iv);
        if (ret)
            return ret;
    }
    if (crow.encryptionScheme && DBRow::ENCR_APPKEY) {
        ret = decryptAES(crow.data, 0, appkey, emptyiv);
        if (ret)
            return ret;
    }
    ret = removeDigest(crow.data, digest);
    if (ret)
        return ret;
    if ((unsigned int)crow.dataSize != crow.data.size())
        return -1;
    ret = digestData(crow.data, 0, dataDigest);
    if (ret)
        return ret;
    if (not equalDigests(digest, dataDigest))
        return -1;
    row = crow;

    return EXIT_SUCCESS;
}

int DBCryptoModule::generateRandIV(RawBuffer &iv)
{
    int ret = -1;
    RawBuffer civ(EVP_MAX_IV_LENGTH);

    if (iv.size() > 0)
        ret = RAND_bytes(&civ[0], civ.size());
    if (1 == ret) {
        iv = civ;
        ret = EXIT_SUCCESS;
    } else {
        ret = -1;
    }

    return ret;
}

int DBCryptoModule::generateKeysFromPassword(const RawBuffer &password,
                                             RawBuffer &key, RawBuffer &iv)
{
    int ret = -1;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned int keyLen = EVP_CIPHER_key_length(cipher);
    unsigned int ivLen = EVP_CIPHER_iv_length(cipher);
#if 0
    const EVP_MD *md = EVP_sha1();
#endif

    if ((password.size() == 0) || (password[0] == 0))
        return ret;
    key.resize(keyLen);
    iv.resize(ivLen);
    if ((ret = generateRandIV(iv)))
        return ret;
    ret = PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char *>(&password[0]),
                                 -1, NULL, 0, 1024, keyLen, &key[0]);
    if (ret != 1)
        return -1;
    else
        ret = EXIT_SUCCESS;
#if 0
    ret = EVP_BytesToKey(cipher, md, NULL,
                         const_cast<const unsigned char *>(&password[0]),
                         strlen(reinterpret_cast<const char *>(&password[0])),
                         1, &key[0], &iv[0]);
    LogDebug("Generated key len: " << ret);
    if (ret > 0)
        ret = EXIT_SUCCESS;
#endif

    return ret;
}

int DBCryptoModule::cryptAES(RawBuffer &data, int len, const RawBuffer &key,
                             const RawBuffer &iv)
{
    int ret = -1;
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned int keyLen = EVP_CIPHER_key_length(cipher);
    unsigned int ivLen = EVP_CIPHER_iv_length(cipher);
    int maxBufLen;
    int outl, outlf;

    if (keyLen <= 0)
        return ret;
    if (key.size() != keyLen)
        return ret;
    if (data.size() == 0)
        return ret;
    /* iv may be empty */
    if (iv.size() > 0)
        if (iv.size() != ivLen)
            return -1;
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
    if (ret != 1)
        return -1;
    EVP_CIPHER_CTX_set_padding(&ctx, 1);
    ret = EVP_EncryptUpdate(&ctx, &buf[0], &outl, &data[0], len);
    if (ret != 1)
        return -1;
    ret = EVP_EncryptFinal_ex(&ctx, &buf[outl], &outlf);
    if (ret != 1)
        return -1;
    LogDebug("Total out len: " << outl + outlf);
    EVP_CIPHER_CTX_cleanup(&ctx);
    data.assign(buf.begin(), buf.end());
    data.resize(outl + outlf);

    return EXIT_SUCCESS;
}

int DBCryptoModule::decryptAES(RawBuffer &data, int len, const RawBuffer &key,
                               const RawBuffer &iv)
{
    int ret = -1;
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned int keyLen = EVP_CIPHER_key_length(cipher);
    unsigned int ivLen = EVP_CIPHER_iv_length(cipher);
    int maxBufLen;
    int outl, outlf;

    if (keyLen <= 0)
        return ret;
    if (key.size() != keyLen)
        return ret;
    if (iv.size() > 0)
        if (iv.size() != ivLen)
            return -1;
    if (0 == len)
        len = data.size();

    maxBufLen = len + EVP_CIPHER_block_size(cipher) + 1;

    LogDebug("buf len: " << maxBufLen);
    LogDebug("data len: " << len);

    RawBuffer buf(maxBufLen, 0);

    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_DecryptInit_ex(&ctx, cipher, NULL, &key[0], &iv[0]);
    if (ret != 1)
        return -1;
    EVP_CIPHER_CTX_set_padding(&ctx, 1);
    ret = EVP_DecryptUpdate(&ctx, &buf[0], &outl, &data[0], len);
    if (ret != 1)
        return -1;
    ret = EVP_DecryptFinal_ex(&ctx, &buf[outl], &outlf);
    if (ret != 1)
        return -1;
    LogDebug("Total out len: " << outl + outlf);
    EVP_CIPHER_CTX_cleanup(&ctx);
    if ((outl + outlf) == 0)
        return -1;
    data.assign(buf.begin(), buf.end());
    data.resize(outl + outlf);

    return EXIT_SUCCESS;
}

int DBCryptoModule::digestData(const RawBuffer &data, int len, RawBuffer &digest)
{
    int ret = -1;
    EVP_MD_CTX ctx;
    const EVP_MD *md = EVP_sha1();
    unsigned int dlen;

    if (data.size() == 0)
        return -1;
    if (0 == len)
        len = data.size();

    ret = EVP_DigestInit(&ctx, md);
    if (ret != 1)
        return -1;
    ret = EVP_DigestUpdate(&ctx, &data[0], len);
    if (ret != 1)
        return -1;
    digest.resize(EVP_MAX_MD_SIZE);
    ret = EVP_DigestFinal(&ctx, &digest[0], &dlen);
    if (ret != 1)
        return -1;
    if (dlen != EVP_MAX_MD_SIZE)
        digest.resize(dlen);

    return EXIT_SUCCESS;
}

int DBCryptoModule::encBase64(RawBuffer &data)
{
    Base64Encoder benc;
    RawBuffer encdata;

    benc.append(data);
    benc.finalize();
    encdata = benc.get();

    if (encdata.size() == 0)
        return -1;

    data = std::move(encdata);

    return EXIT_SUCCESS;
}

int DBCryptoModule::decBase64(RawBuffer &data)
{
    Base64Decoder bdec;

    bdec.reset();
    bdec.append(data);
    if (not bdec.finalize())
        return -1;

    RawBuffer decdata = bdec.get();
    if (decdata.size() == 0)
        return -1;

    data = std::move(decdata);

    return EXIT_SUCCESS;
}

bool DBCryptoModule::equalDigests(RawBuffer &dig1, RawBuffer &dig2)
{
    if ((dig1.size() != SHA_DIGEST_LENGTH) ||
        (dig2.size() != SHA_DIGEST_LENGTH))
        return false;
    return std::equal(dig1.begin(), dig1.end(), &dig2[0]);
}

} // namespace CKM

