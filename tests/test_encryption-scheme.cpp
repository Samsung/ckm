/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file       test_encryption-scheme.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include <scheme-test.h>

using namespace CKM;

namespace {
// this is done to limit the amount of code included in binary
const int OLD_ENC_SCHEME  = 0;
const int NEW_ENC_SCHEME  = 1;
} // namespace anonymous


BOOST_AUTO_TEST_SUITE(ENCRYPTION_SCHEME_TEST)

// Test database should have the old scheme
BOOST_AUTO_TEST_CASE(T010_Check_old_scheme) {
    SchemeTest test;
    test.RestoreDb();

    ItemFilter filter;
    test.CheckSchemeVersion(filter, OLD_ENC_SCHEME);
}

// Newly written data should use the new scheme
BOOST_AUTO_TEST_CASE(T020_Check_new_scheme) {
    SchemeTest test;
    test.RemoveUserData();
    test.FillDb();

    ItemFilter filter;
    test.CheckSchemeVersion(filter, NEW_ENC_SCHEME);
}

BOOST_AUTO_TEST_CASE(T030_Remove_old_scheme) {
    SchemeTest test;
    test.RestoreDb();
    test.RemoveAll();

    size_t aliases = test.CountObjects();
    BOOST_REQUIRE_MESSAGE(aliases == 0, "All aliases should be removed");
}

BOOST_AUTO_TEST_CASE(T040_Remove_new_scheme) {
    SchemeTest test;
    test.RemoveUserData();
    test.FillDb();
    test.RemoveAll();

    size_t aliases = test.CountObjects();
    BOOST_REQUIRE_MESSAGE(aliases == 0, "All aliases should be removed");
}

// Reading old db should reencrypt objects with new scheme
BOOST_AUTO_TEST_CASE(T100_Read) {
    SchemeTest test;
    test.RestoreDb();
    test.ReadAll();

    ItemFilter filter;
    filter.exportableOnly = true;
    test.CheckSchemeVersion(filter, NEW_ENC_SCHEME);
}

BOOST_AUTO_TEST_CASE(T110_Count_objects_after_read) {
    SchemeTest test;
    test.RestoreDb();
    size_t orig = test.CountObjects();
    BOOST_REQUIRE_MESSAGE(orig > 0, "No objects in db");

    test.ReadAll();

    size_t current = test.CountObjects();
    BOOST_REQUIRE_MESSAGE(current == orig,
                          "Original number of objects: " << orig << " Current: " << current);
}

// Reading old db with incorrect passwords should leave the scheme unchanged
BOOST_AUTO_TEST_CASE(T120_Read_wrong_pass) {
    SchemeTest test;
    test.RestoreDb();
    test.ReadAll(true);

    ItemFilter filter;
    test.CheckSchemeVersion(filter, OLD_ENC_SCHEME);
}

// Signing/verification should reencrypt objects with new scheme
BOOST_AUTO_TEST_CASE(T200_SignVerify) {
    SchemeTest test;
    test.RestoreDb();
    test.SignVerify();

    ItemFilter filter(DataType::KEY_RSA_PUBLIC, DataType::KEY_RSA_PRIVATE);
    test.CheckSchemeVersion(filter, NEW_ENC_SCHEME);
}

// Encryption/decryption should reencrypt objects with new scheme
BOOST_AUTO_TEST_CASE(T210_EncryptDecrypt) {
    SchemeTest test;
    test.RestoreDb();
    test.EncryptDecrypt();

    ItemFilter filter1(DataType::KEY_RSA_PUBLIC, DataType::KEY_RSA_PRIVATE);
    test.CheckSchemeVersion(filter1, NEW_ENC_SCHEME);

    ItemFilter filter2(DataType::KEY_AES);
    test.CheckSchemeVersion(filter2, NEW_ENC_SCHEME);
}

// Chain creation should reencrypt objects with new scheme
BOOST_AUTO_TEST_CASE(T220_CreateChain) {
    SchemeTest test;
    test.RestoreDb();
    test.CreateChain();

    // non exportable certificates and certificates protected with passwords can't be used for chain
    // creation
    ItemFilter filter1(DataType::CERTIFICATE);
    filter1.exportableOnly = true;
    filter1.noPassword = true;
    test.CheckSchemeVersion(filter1, NEW_ENC_SCHEME);

    ItemFilter filter2(DataType::CHAIN_CERT_0, DataType::CHAIN_CERT_15);
    filter2.exportableOnly = true;
    filter2.noPassword = true;
    test.CheckSchemeVersion(filter2, NEW_ENC_SCHEME);
}

BOOST_AUTO_TEST_SUITE_END()
