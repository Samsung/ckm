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
 * @file       scheme-test.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */
#include <scheme-test.h>

#include <sys/smack.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <stdexcept>

#include <smack-access.h>

using namespace CKM;
using namespace std;

namespace {
const uid_t UID = 7654;
const gid_t GID = 7654;
const char* const DBPASS = "db-pass";
const char* const LABEL = "my-label";
const string TEST_DATA_STR = "test-data";
RawBuffer TEST_DATA(TEST_DATA_STR.begin(), TEST_DATA_STR.end());
const Password TEST_PASS = "custom user password";

enum {
    NO_PASS = 0,
    PASS = 1
};

enum {
    NO_EXP = 0,
    EXP = 1
};

// [password][exportable]
Policy policy[2][2] = {
        {{ Password(), false }, { Password(), true }},
        {{ TEST_PASS,  false }, { TEST_PASS,  true }},
};

struct Group {
    enum {
        KEY_PAIR,
        CERT_CHAIN,
        SINGLE_ITEM
    } type;
    Items items;
};

Group GROUPS[] = {
    // Data
    { Group::SINGLE_ITEM, {
            Item("data-alias1", DataType::BINARY_DATA,  policy[NO_PASS][EXP])
    }},
    { Group::SINGLE_ITEM, {
            Item("data-alias2", DataType::BINARY_DATA,  policy[PASS][EXP])
    }},

    // RSA keys
    { Group::KEY_PAIR, {
            Item("key-rsa-alias-prv1", DataType::KEY_RSA_PRIVATE,  policy[NO_PASS][NO_EXP]),
            Item("key-rsa-alias-pub1", DataType::KEY_RSA_PUBLIC,   policy[NO_PASS][NO_EXP])
    }},
    { Group::KEY_PAIR, {
            Item("key-rsa-alias-prv2", DataType::KEY_RSA_PRIVATE,  policy[NO_PASS][EXP]),
            Item("key-rsa-alias-pub2", DataType::KEY_RSA_PUBLIC,   policy[NO_PASS][EXP]),
    }},
    { Group::KEY_PAIR, {
            Item("key-rsa-alias-prv3", DataType::KEY_RSA_PRIVATE,  policy[PASS][NO_EXP]),
            Item("key-rsa-alias-pub3", DataType::KEY_RSA_PUBLIC,   policy[PASS][NO_EXP]),
    }},
    { Group::KEY_PAIR, {
            Item("key-rsa-alias-prv4", DataType::KEY_RSA_PRIVATE,  policy[PASS][EXP]),
            Item("key-rsa-alias-pub4", DataType::KEY_RSA_PUBLIC,   policy[PASS][EXP]),
    }},
    // different policies
    { Group::KEY_PAIR, {
            Item("key-rsa-alias-prv5", DataType::KEY_RSA_PRIVATE,  policy[PASS][NO_EXP]),
            Item("key-rsa-alias-pub5", DataType::KEY_RSA_PUBLIC,   policy[NO_PASS][EXP]),
    }},

    // AES
    { Group::SINGLE_ITEM, {
            Item("key-aes-alias1",     DataType::KEY_AES,          policy[NO_PASS][NO_EXP]),
    }},
    { Group::SINGLE_ITEM, {
            Item("key-aes-alias2",     DataType::KEY_AES,          policy[NO_PASS][EXP]),
    }},
    { Group::SINGLE_ITEM, {
            Item("key-aes-alias3",     DataType::KEY_AES,          policy[PASS][NO_EXP]),
    }},
    { Group::SINGLE_ITEM, {
            Item("key-aes-alias4",     DataType::KEY_AES,          policy[PASS][EXP]),
    }},

    // Certificates
    { Group::CERT_CHAIN, {
            Item("cert-root-alias1",   DataType::CERTIFICATE,      policy[NO_PASS][NO_EXP]),
            Item("cert-im-ca-alias1",  DataType::CERTIFICATE,      policy[NO_PASS][NO_EXP]),
            Item("cert-leaf-alias1",   DataType::CERTIFICATE,      policy[NO_PASS][NO_EXP]),
    }},
    { Group::CERT_CHAIN, {
            Item("cert-root-alias2",   DataType::CERTIFICATE,      policy[NO_PASS][EXP]),
            Item("cert-im-ca-alias2",  DataType::CERTIFICATE,      policy[NO_PASS][EXP]),
            Item("cert-leaf-alias2",   DataType::CERTIFICATE,      policy[NO_PASS][EXP]),
    }},
    { Group::CERT_CHAIN, {
            Item("cert-root-alias3",   DataType::CERTIFICATE,      policy[PASS][NO_EXP]),
            Item("cert-im-ca-alias3",  DataType::CERTIFICATE,      policy[PASS][NO_EXP]),
            Item("cert-leaf-alias3",   DataType::CERTIFICATE,      policy[PASS][NO_EXP]),
    }},
    { Group::CERT_CHAIN, {
            Item("cert-root-alias4",   DataType::CERTIFICATE,      policy[PASS][EXP]),
            Item("cert-im-ca-alias4",  DataType::CERTIFICATE,      policy[PASS][EXP]),
            Item("cert-leaf-alias4",   DataType::CERTIFICATE,      policy[PASS][EXP]),
    }},

    // PKCS
    { Group::SINGLE_ITEM, {
            Item("pkcs-alias1",        DataType::CHAIN_CERT_0,     policy[NO_PASS][NO_EXP]),
    }},
    { Group::SINGLE_ITEM, {
            Item("pkcs-alias2",        DataType::CHAIN_CERT_0,     policy[NO_PASS][EXP]),
    }},
    { Group::SINGLE_ITEM, {
            Item("pkcs-alias3",        DataType::CHAIN_CERT_0,     policy[PASS][NO_EXP]),
    }},
    { Group::SINGLE_ITEM, {
            Item("pkcs-alias4",        DataType::CHAIN_CERT_0,     policy[PASS][EXP]),
    }},
};

const size_t CHAIN_SIZE = 3;

// TEST_ROOT_CA, expires 2035
std::string TEST_ROOT_CA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDnzCCAoegAwIBAgIJAMH/ADkC5YSTMA0GCSqGSIb3DQEBBQUAMGYxCzAJBgNV\n"
    "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQKDARBQ01FMRAwDgYD\n"
    "VQQLDAdUZXN0aW5nMSEwHwYDVQQDDBhUZXN0IHJvb3QgY2EgY2VydGlmaWNhdGUw\n"
    "HhcNMTQxMjMwMTcyMTUyWhcNMjQxMjI3MTcyMTUyWjBmMQswCQYDVQQGEwJBVTET\n"
    "MBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UECgwEQUNNRTEQMA4GA1UECwwHVGVz\n"
    "dGluZzEhMB8GA1UEAwwYVGVzdCByb290IGNhIGNlcnRpZmljYXRlMIIBIjANBgkq\n"
    "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0EJRdUtd2th0vTVF7QxvDKzyFCF3w9vC\n"
    "9IDE/Yr12w+a9jd0s7/eG96qTHIYffS3B7x2MB+d4n+SR3W0qmYh7xk8qfEgH3da\n"
    "eDoV59IZ9r543KM+g8jm6KffYGX1bIJVVY5OhBRbO9nY6byYpd5kbCIUB6dCf7/W\n"
    "rQl1aIdLGFIegAzPGFPXDcU6F192686x54bxt/itMX4agHJ9ZC/rrTBIZghVsjJo\n"
    "5/AH5WZpasv8sfrGiiohAxtieoYoJkv5MOYP4/2lPlOY+Cgw1Yoz+HHv31AllgFs\n"
    "BquBb/kJVmCCNsAOcnvQzTZUsW/TXz9G2nwRdqI1nSy2JvVjZGsqGQIDAQABo1Aw\n"
    "TjAdBgNVHQ4EFgQUt6pkzFt1PZlfYRL/HGnufF4frdwwHwYDVR0jBBgwFoAUt6pk\n"
    "zFt1PZlfYRL/HGnufF4frdwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOC\n"
    "AQEAld7Qwq0cdzDQ51w1RVLwTR8Oy25PB3rzwEHcSGJmdqlMi3xOdaz80S1R1BBX\n"
    "ldvGBG5Tn0vT7xSuhmSgI2/HnBpy9ocHVOmhtNB4473NieEpfTYrnGXrFxu46Wus\n"
    "9m/ZnugcQ2G6C54A/NFtvgLmaC8uH8M7gKdS6uYUwJFQEofkjmd4UpOYSqmcRXhS\n"
    "Jzd5FYFWkJhKJYp3nlENSOD8CUFFVGekm05nFN2gRVc/qaqQkEX77+XYvhodLRsV\n"
    "qMn7nf7taidDKLO2T4bhujztnTYOhhaXKgPy7AtZ28N2wvX96VyAPB/vrchGmyBK\n"
    "kOg11TpPdNDkhb1J4ZCh2gupDg==\n"
    "-----END CERTIFICATE-----\n";

// TEST_IM_CA, signed by TEST_ROOT_CA, expires 2035
std::string TEST_IM_CA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDljCCAn6gAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwZjELMAkGA1UEBhMCQVUx\n"
    "EzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAoMBEFDTUUxEDAOBgNVBAsMB1Rl\n"
    "c3RpbmcxITAfBgNVBAMMGFRlc3Qgcm9vdCBjYSBjZXJ0aWZpY2F0ZTAeFw0xNTAx\n"
    "MTYxNjQ1MzRaFw0zNTAxMTExNjQ1MzRaMGQxCzAJBgNVBAYTAkFVMRMwEQYDVQQI\n"
    "DApTb21lLVN0YXRlMQ0wCwYDVQQKDARBQ01FMRAwDgYDVQQLDAdUZXN0aW5nMR8w\n"
    "HQYDVQQDDBZUZXN0IElNIENBIGNlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEF\n"
    "AAOCAQ8AMIIBCgKCAQEAzmBF78qClgoKfnLAncMXZwZ14TW+5kags1+QCYeg3c7j\n"
    "L9+RvDxIaX2tKf1sukJcwQfYqUlQkwt+58LMOb2ORtkpj8Or6WCWCZ0BzneT8ug7\n"
    "nxJT4m9+bohMF0JoKjjB2H4KNMHamLIwUxRKt6nyfk81kVhJOi2vzzxd+UCPi6Pc\n"
    "UAbJNH48eNgOIg55nyFovVzYj8GIo/9GvHJj83PPa/KlJZ+Z1qZASZZ/VYorplVT\n"
    "thsHXKfejhFy5YJ9t7n/vyAQsyBsagZsvX19xnH41fbYXHKf8UbXG23rNaZlchs6\n"
    "XJVLQdzOpj3WTj/lCocVHqLaZISLhNQ3aI7kUBUdiwIDAQABo1AwTjAdBgNVHQ4E\n"
    "FgQUoCYNaCBP4jl/3SYQuK8Ka+6i3QEwHwYDVR0jBBgwFoAUt6pkzFt1PZlfYRL/\n"
    "HGnufF4frdwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjRzWiD97\n"
    "Htv4Kxpm3P+C+xP9AEteCJfO+7p8MWgtWEJOknJyt55zeKS2JwZIq57KcbqD8U7v\n"
    "vAUx1ymtUhlFPFd7J1mJ3pou+3aFYmGShYhGHpbrmUwjp7HVP588jrW1NoZVHdMc\n"
    "4OgJWFrViXeu9+maIcekjMB/+9Y0dUgQuK5ZuT5H/Jwet7Th/o9uufTUZjBzRvrB\n"
    "pbXgQpqgME2av4Q/6LuldPCTHLtWXgFUU2R+yCGmuGilvhFJnKoQryAbYnIQNWE8\n"
    "SLoHQ9s1i7Zyb7HU6UAaqMOz15LBkyAqtNyJcO2p7Q/p5YK0xfD4xisI5qXucqVm\n"
    "F2obL5qJSTN/RQ==\n"
    "-----END CERTIFICATE-----\n";

// TEST_LEAF, signed by TEST_IM_CA, expires 2035
std::string TEST_LEAF =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDOzCCAiMCAQEwDQYJKoZIhvcNAQEFBQAwZDELMAkGA1UEBhMCQVUxEzARBgNV\n"
    "BAgMClNvbWUtU3RhdGUxDTALBgNVBAoMBEFDTUUxEDAOBgNVBAsMB1Rlc3Rpbmcx\n"
    "HzAdBgNVBAMMFlRlc3QgSU0gQ0EgY2VydGlmaWNhdGUwHhcNMTUwMTE2MTY0ODE0\n"
    "WhcNMzUwMTExMTY0ODE0WjBjMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1T\n"
    "dGF0ZTENMAsGA1UECgwEQUNNRTEQMA4GA1UECwwHVGVzdGluZzEeMBwGA1UEAwwV\n"
    "VGVzdCBsZWFmIGNlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
    "CgKCAQEAzTdDIa2tDmRxFnIgiG+mBz8GoSVODs0ImNQGbqj+pLhBOFRH8fsah4Jl\n"
    "z5YF9KwhMVLknnHGFLE/Nb7Ac35kEzhMQMpTRxohW83oxw3eZ8zN/FBoKqg4qHRq\n"
    "QR8kS10YXTgrBR0ex/Vp+OUKEw6h7yL2r4Tpvrn9/qHwsxtLxqWbDIVf1O9b1Lfc\n"
    "bllYMdmV5E62yN5tcwrDP8gvHjFnVeLzrG8wTpc9FR90/0Jkfp5jAJcArOBLrT0E\n"
    "4VRqs+4HuwT8jAwFAmNnc7IYX5qSjtSWkmmHe73K/lzB+OiI0JEc/3eWUTWqwTSk\n"
    "4tNCiQGBKJ39LXPTBBJdzmxVH7CUDQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAp\n"
    "UdDOGu3hNiG+Vn10aQ6B1ZmOj3t+45gUV3sC+y8hB8EK1g4P5Ke9bVDts0T5eOnj\n"
    "CSc+6VoND5O4adI0IFFRFljHNVnvjeosHfUZNnowsmA2ptQBtC1g5ZKRvKXlkC5/\n"
    "i5BGgRqPFA7y9WB9Y05MrJHf3E+Oz/RBsLeeNiNN+rF5X1vYExvGHpo0M0zS0ze9\n"
    "HtC0aOy8ocsTrQkf3ceHTAXx2i8ftoSSD4klojtWFpWMrNQa52F7wB9nU6FfKRuF\n"
    "Zj/T1JkYXKkEwZU6nAR2jdZp3EP9xj3o15V/tyFcXHx6l8NTxn4cJb+Xe4VquQJz\n"
    "6ON7PVe0ABN/AlwVQiFE\n"
    "-----END CERTIFICATE-----\n";
} // namespace anonymous


SchemeTest::SchemeTest() : m_userChanged(false) {
    m_control = Control::create();
    m_mgr = Manager::create();

    SmackAccess sa;
    sa.add("System", LABEL, "rwx");
    sa.add(LABEL, "System", "rwx");
    sa.add(LABEL, "System::Run", "x");
    sa.apply();
}

SchemeTest::~SchemeTest() {
    try {
        SwitchToRoot();
    } catch (...) {}
}

void SchemeTest::SwitchToUser() {
    if (m_userChanged)
        return;

    if(CKM_API_SUCCESS != m_control->unlockUserKey(UID, DBPASS))
        throw runtime_error("unlockUserKey failed");

    // get calling label
    char* label = NULL;
    if (smack_new_label_from_self(&label) <= 0)
        throw runtime_error("smack_new_label_from_self failed");

    m_origLabel = string(label);
    free(label);

    if(0 > smack_set_label_for_self(LABEL))
        throw runtime_error("smack_set_label_for_self failed");

    if(0 > setegid(GID))
        throw runtime_error("setegid failed");

    if(0 > seteuid(UID))
        throw runtime_error("seteuid failed");

    m_userChanged = true;
}

void SchemeTest::SwitchToRoot() {
    if (!m_userChanged)
        return;

    if(0 > seteuid(0))
        throw runtime_error("seteuid failed");
    if(0 > setegid(0))
        throw runtime_error("setegid failed");

    if(0 > smack_set_label_for_self(m_origLabel.c_str()))
        throw runtime_error("smack_set_label_for_self failed");

    if(m_control->lockUserKey(UID) != CKM_API_SUCCESS)
        throw runtime_error("lockUserKey failed");
}

void SchemeTest::FillDb() {
    // pkcs
    ifstream is("/usr/share/ckm-db-test/encryption-scheme.p12");
    if(!is)
        throw runtime_error("Failed to read pkcs");
    istreambuf_iterator<char> begin(is), end;
    RawBuffer pkcsBuffer(begin, end);
    auto pkcs = PKCS12::create(pkcsBuffer, Password());
    if(pkcs->empty())
        throw runtime_error("Empty pkcs");

    SwitchToUser();

    // certificates
    RawBuffer rootCaBuffer(TEST_ROOT_CA.begin(), TEST_ROOT_CA.end());
    CertificateShPtr rootCa = CKM::Certificate::create(rootCaBuffer, CKM::DataFormat::FORM_PEM);
    RawBuffer imCaBuffer(TEST_IM_CA.begin(), TEST_IM_CA.end());
    CertificateShPtr imCa = CKM::Certificate::create(imCaBuffer, CKM::DataFormat::FORM_PEM);
    RawBuffer leafBuffer(TEST_LEAF.begin(), TEST_LEAF.end());
    CertificateShPtr leaf = CKM::Certificate::create(leafBuffer, CKM::DataFormat::FORM_PEM);

    for(const auto& g:GROUPS) {
        switch (g.type) {
        case Group::KEY_PAIR:
            if(g.items.size() != 2)
                throw runtime_error("Wrong number of keys");
            if( g.items[0].type != DataType::KEY_RSA_PRIVATE ||
                g.items[1].type != DataType::KEY_RSA_PUBLIC)
                throw runtime_error("Invalid item type");

            if(CKM_API_SUCCESS != m_mgr->createKeyPairRSA(1024,
                                                          g.items[0].alias,
                                                          g.items[1].alias,
                                                          g.items[0].policy,
                                                          g.items[1].policy))
                throw runtime_error("createKeyPair failed");
            break;

        case Group::CERT_CHAIN:
            if(g.items.size() != CHAIN_SIZE)
                throw runtime_error("Wrong number of certificates");
            if( g.items[0].type != DataType::CERTIFICATE ||
                g.items[1].type != DataType::CERTIFICATE ||
                g.items[2].type != DataType::CERTIFICATE)
                throw runtime_error("Invalid item type");

            if(CKM_API_SUCCESS != m_mgr->saveCertificate(g.items[0].alias, rootCa, g.items[0].policy))
                throw runtime_error("saveCertificate failed");
            if(CKM_API_SUCCESS != m_mgr->saveCertificate(g.items[1].alias, imCa, g.items[1].policy))
                throw runtime_error("saveCertificate failed");
            if(CKM_API_SUCCESS != m_mgr->saveCertificate(g.items[2].alias, leaf, g.items[2].policy))
                throw runtime_error("saveCertificate failed");
            break;

        default:
            for(const auto& i:g.items) {
                switch (i.type) {
                case DataType::BINARY_DATA:
                    if(CKM_API_SUCCESS != m_mgr->saveData(i.alias, TEST_DATA, i.policy))
                        throw runtime_error("saveData failed");
                    break;

                case DataType::KEY_AES:
                    if(CKM_API_SUCCESS != m_mgr->createKeyAES(256, i.alias, i.policy))
                        throw runtime_error("createKeyAES failed");
                    break;

                case DataType::CHAIN_CERT_0:    // PKCS
                    if(CKM_API_SUCCESS != m_mgr->savePKCS12(i.alias, pkcs, i.policy, i.policy))
                        throw runtime_error("savePkcs12 failed");
                    break;

                default:
                    throw runtime_error("unsupported data type");
                }
            }
            break;
        }
    }
}
