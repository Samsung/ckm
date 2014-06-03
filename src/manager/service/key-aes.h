#pragma once

namespace CKM {

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
	KeyAES(const RawBuffer &key, const RawBuffer &iv = RawBuffer());

	KeyAES(const KeyAES &key);
	KeyAES(KeyAES &&key);
	KeyAES& operator=(const KeyAES &key);
	KeyAES& operator=(KeyAES &&key);
	
	// iv must be set to perform encrypt/decrypt operation
	// iv may be set in constructor or directly in encrypt/decrypt operation
	RawBuffer encrypt(const RawBuffer &data, const RawBuffer &iv = RawBuffer());
	RawBuffer decrypt(const RawBuffer &data, const RawBuffer &iv = RawBuffer());
	
	RawBuffer getKey();
	
	virtual ~KeyAES(){}
private:
	// TODO: should we keep key in plain text RawBuffer or in AES_KEY structure.
};

} // namespace CKM

