#pragma once

namespace CKM {

// typedef std::vector<unsigned char> RawData; // must be defined in common header.

// Check encryption shema in openssl
// * what about data length after decryption?
// * do we need reset EVP_CONTEXT_CTX before each decryption?
class KeyAES {
public:
	// the iv is for inicialization vector, in some special cases
	// we may not be able to set up iv in constructor.
	// For example KeyProvider will not know the iv, it may set only the
	// key information.
	KeyAES(){};
	KeyAES(const RawData &key, const RawData &iv = RawData());

	KeyAES(const KeyAES &key);
	KeyAES(KeyAES &&key);
	KeyAES& operator=(const KeyAES &key);
	KeyAES& operator=(KeyAES &&key);
	
	// iv must be set to perform encrypt/decrypt operation
	// iv may be set in constructor or directly in encrypt/decrypt operation
	RawData encrypt(const RawData &data, const RawData &iv = RawData());
	RawData decrypt(const RawData &data, const RawData &iv = RawData());
	
	RawData getKey();
	
	virtual ~KeyAES(){}
private:
	// TODO: should we keep key in plain text RawBuffer or in AES_KEY structure.
};

} // namespace CKM
