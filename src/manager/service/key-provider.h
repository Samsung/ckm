#pragma once

#include <ckm-key-provider.h>
#include <ckm/ckm-type.h>
#include <key-aes.h>
#include <dpl/exception.h>

namespace CKM {

class WrappedKeyMaterialContainer{
public:
	WrappedKeyMaterialContainer();
	WrappedKeyMaterialContainer(const unsigned char*);
	WrappedKeyMaterial& getWrappedKeyMaterial();
	~WrappedKeyMaterialContainer();
private:
	WrappedKeyMaterial *wrappedKeyMaterial;
};

class KeyMaterialContainer{
public:
	class Exception{
	public:
		DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
	};
	KeyMaterialContainer();
	KeyMaterialContainer(const unsigned char*);
	KeyMaterial& getKeyMaterial();
	~KeyMaterialContainer();
private:
	KeyMaterial *keyMaterial;
};


// This is internal api so all functions should throw exception on errors.
class KeyProvider {
public:
	class Exception {
	public:
		DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
		DECLARE_EXCEPTION_TYPE(Base, InitFailed)
		DECLARE_EXCEPTION_TYPE(Base, GenFailed)
		DECLARE_EXCEPTION_TYPE(Base, WrapFailed)
		DECLARE_EXCEPTION_TYPE(Base, UnwrapFailed)
		DECLARE_EXCEPTION_TYPE(Base, PassWordError)
		DECLARE_EXCEPTION_TYPE(Base, InputParamError)
	};

	// To store in std containers
	KeyProvider();
	// In constructor you must check if SKMM is initialized. On error -> exception
	// keyInWrapForm should be used like this:
	// if (keyInWrapForm.size() != sizeof(WrappedKeyMaterial))
	//	 throw exception; // buffer does not have proper size to store WrappedKeyMaterial
	// WrappedKeyMaterial *wkm = static_cast<WrappedKeyMaterial>(keyInWrapForm.data());
	KeyProvider(const RawBuffer &domainKEKInWrapForm, const std::string &password);

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
	RawBuffer getWrappedDomainKEK(const std::string &password);

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
		const std::string &oldPass,
		const std::string &newPass);

	// First run of application for some user. DomainKEK was not created yet. We must create one.
	// This key will be used to encrypt user database.
	static RawBuffer generateDomainKEK(const std::string &user, const std::string &userPassword);

	// This will be called by framework at the begin of the program
	static int initializeLibrary();
	// This will be called by framework at the end of the program
	static int closeLibrary();

	virtual ~KeyProvider();
private:
	// KeyMaterialContainer class
	KeyMaterialContainer *m_kmcDKEK;
	bool m_isInitialized;
	static bool s_isInitialized;
};

} // namespace CKM

