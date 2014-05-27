#pragma once

struct KeyMaterial;

namespace CKM {

// typedef std::vector<unsigned char> RawData; this must be defined in common header.

// This is internal api so all functions should throw exception on errors.

class KeyProvider {
    // In constructor you must check if SKMM is initialized. On error -> exception
    // keyInWrapForm should be used like this:
    // if (keyInWrapForm.size() != sizeof(WrappedKeyMaterial))
    //     throw exception; // buffer does not have proper size to store WrappedKeyMaterial
    // WrappedKeyMaterial *wkm = static_cast<WrappedKeyMaterial>(keyInWrapForm.data());
    KeyProvider(const RawData &domainKEKInWrapForm, const RawData &password);

    // Returns Key used to decrypt database. 
    KeyAES getDomainKEK();

    // Returns Key in form used to store key in file
    // Requied by Control::resetPassword(const RawData &newPassword);
    // This api should be used only on Tizen 2.2.1
    RawData getDomainKEK(const std::string &password);

    // EncryptedKey key extracted from database. Used to encrypt application data.
    // This key will be used to decrypt/encrypt data in ROW
    KeyAES decryptDEK(const RawData &encrypedDEKInWrapForm);

    // Returns WRAPPED DEK. This will be written to datbase.
    // This key will be used to encrypt all application information.
    // All application are identified by smackLabel.
    RawData generateDEK(const std::string &smackLabel);

    // used by change user password. On error -> exception
    static RawData reencrypt(const RawData &domainKEKInWrapForm, const RawData &oldPass, const RawData &newPass);

    // First run of application for some user. DomainKEK was not created yet. We must create one.
    // This key will be used to encrypt user database.
    static RawData generateDomainKEK(const std::string &user, const RawData &userPassword);

    // This will be called by framework at the begin of the program
    static initializeLibrary();
    // This will be called by framework at the end of the program
    static closeLibrary();

    virtual ~KeyProvider();
private:
    KeyMaterial* m_dkek;
};

} // namespace CKM
