#define BOOST_TEST_MODULE KEY_MANAGER_TEST
#include <boost/test/included/unit_test.hpp>
#include <key-provider.h>

#define PASSWORD "12345TIZEN12345AAAAAAAAA"
#define INCORRECT_PASSWORD "AAAAAAAAAAAAAAAAAAAAA"
#define NEW_PASSWORD "NEW12345TIZEN12345NEW"

#define USERNAME_SHORT "AB"
#define USERNAME_LONG "SOFTWARE_CENTER_SYSTEM_SW_LAB_SECURITY_PART"
#define SMACK_LABEL_1 "SAMPLE_SMACK_LABEL_1"
#define SMACK_LABEL_2 "SAMPLE_SMACK_LABEL_2"

CKM::KeyProvider keyProvider;
CKM::RawBuffer rb_test;
CKM::RawBuffer rb_DEK1;
CKM::RawBuffer rb_pureDEK1;

// Test suite for key-provider module.
BOOST_AUTO_TEST_SUITE(S1_KEY_PROVIDER)

BOOST_AUTO_TEST_CASE(T00100_initialize){
    boost::unit_test::unit_test_log.set_threshold_level( boost::unit_test::log_test_units);
    BOOST_CHECK_NO_THROW(CKM::KeyProvider::initializeLibrary());
}

BOOST_AUTO_TEST_CASE(T00200_generateDomainKEK){
    rb_test.clear();
    BOOST_CHECK(!(rb_test = CKM::KeyProvider::generateDomainKEK(std::string(USERNAME_LONG),
            std::string(PASSWORD))).empty());
}

BOOST_AUTO_TEST_CASE(T00300_construct){
    BOOST_CHECK_NO_THROW(keyProvider = CKM::KeyProvider(rb_test, std::string(PASSWORD)));
}

BOOST_AUTO_TEST_CASE(T00301_construct_incorrect_password){
    BOOST_CHECK_THROW(keyProvider = CKM::KeyProvider(rb_test, std::string(INCORRECT_PASSWORD)),
            CKM::KeyProvider::Exception::UnwrapFailed);
}

BOOST_AUTO_TEST_CASE(T00400_isInitialized){
    BOOST_CHECK(keyProvider.isInitialized());
}

BOOST_AUTO_TEST_CASE(T00500_getPureDomainKEK){
    BOOST_CHECK_NO_THROW(rb_test = keyProvider.getPureDomainKEK());
}

BOOST_AUTO_TEST_CASE(T00600_getWrappedDomainKEK){
    BOOST_CHECK_NO_THROW(rb_test = keyProvider.getWrappedDomainKEK(PASSWORD));
}

BOOST_AUTO_TEST_CASE(T00700_generateDEK){
    rb_DEK1.clear();
    BOOST_CHECK_NO_THROW(rb_DEK1 = keyProvider.generateDEK(std::string(SMACK_LABEL_1)));
}

BOOST_AUTO_TEST_CASE(T00800_getPureDEK){
    rb_pureDEK1.clear();
    BOOST_CHECK_NO_THROW(rb_pureDEK1 = keyProvider.getPureDEK(rb_DEK1));
}

BOOST_AUTO_TEST_CASE(T00900_reencrypt){
    BOOST_CHECK_NO_THROW(CKM::KeyProvider::reencrypt(rb_test, std::string(PASSWORD),
            std::string(NEW_PASSWORD)));
}

BOOST_AUTO_TEST_CASE(T00901_reencrypt_incorrect_password){
    BOOST_CHECK_THROW((rb_test = CKM::KeyProvider::reencrypt(rb_test, std::string(INCORRECT_PASSWORD),
            std::string(NEW_PASSWORD))), CKM::KeyProvider::Exception::UnwrapFailed);
}

BOOST_AUTO_TEST_CASE(T01000_getPureDEK_after_reencrypt){
    BOOST_CHECK_NO_THROW(keyProvider.getPureDEK(rb_DEK1));
}

BOOST_AUTO_TEST_CASE(T10000_closeLibrary){
    BOOST_CHECK_NO_THROW(CKM::KeyProvider::closeLibrary());
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(S2_CRYPTO_MODULE)

BOOST_AUTO_TEST_CASE(T00100_initialize){
    BOOST_CHECK(1);
}

BOOST_AUTO_TEST_SUITE_END()
