#pragma once

#include <map>
#include <ckm/ckm-type.h>

namespace CKM {

struct DBRow {
	static const int ENCR_BASE64 =   1 << 0;
	static const int ENCR_APPKEY =   1 << 1;
	static const int ENCR_PASSWORD = 1 << 2;

	std::string user;
	std::string smackLabel;
	int dataType;                       // cert/key/data
	int algorithmType;                  // AES mode ?
	int encryptionScheme;               // for example: (ENCR_BASE64 | ENCR_PASSWORD)
	RawBuffer iv;                       // encoded in base64
	int dataSize;                       // size of information without hash and padding
	RawBuffer data;
};


class DBCryptoModule {
public:
	DBCryptoModule(RawBuffer &domainKEK);

	int decryptRow(const RawBuffer &password, DBRow &row);
	int encryptRow(const RawBuffer &password, DBRow &row);

	bool haveKey(const std::string &smackLabel);
	int pushKey(const std::string &smackLabel, const RawBuffer &applicationKey);

private:
	RawBuffer m_domainKEK;
	std::map<std::string, RawBuffer> m_keyMap;

    /* TODO: Move it to private/protected after tests (or remove if not needed) */
    int cryptAES(RawBuffer &data, int len, const RawBuffer &key,
                 const RawBuffer &iv);
    int decryptAES(RawBuffer &data, int len, const RawBuffer &key,
                   const RawBuffer &iv);
    int decBase64(RawBuffer &data);
    int digestData(const RawBuffer &data, int len, RawBuffer &digest);
    int encBase64(RawBuffer &data);
    bool equalDigests(RawBuffer &dig1, RawBuffer &dig2);
    int insertDigest(RawBuffer &data, const int dataSize);
    int generateKeysFromPassword(const RawBuffer &password,
                                 RawBuffer &key, RawBuffer &iv);
    int generateRandIV(RawBuffer &iv);
    int removeDigest(RawBuffer &data, RawBuffer &digest);
};

} // namespace CKM

