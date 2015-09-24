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
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <fstream>
#include <stdexcept>

#include <boost/test/unit_test.hpp>

#include <smack-access.h>

#include <db-crypto.h>
#include <file-system.h>
#include <key-provider.h>
#include <db-row.h>
#include <crypto-init.h>

using namespace CKM;
using namespace std;

namespace {
const uid_t UID = 7654;
const gid_t GID = 7654;
const char* const DBPASS = "db-pass";
const char* const LABEL = "my-label";
const Label DB_LABEL = "/" + string(LABEL);
const int ENC_SCHEME_OFFSET = 24;
const string TEST_DATA_STR = "test-data";
RawBuffer TEST_DATA(TEST_DATA_STR.begin(), TEST_DATA_STR.end());
const Password TEST_PASS = "custom user password";
const size_t IV_LEN = 16;
const size_t CHAIN_LEN = 3;

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
        SINGLE_ITEM,
        KEY_PAIR_RSA,
        CERT_CHAIN
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
    { Group::KEY_PAIR_RSA, {
            Item("key-rsa-alias-prv1", DataType::KEY_RSA_PRIVATE,  policy[NO_PASS][NO_EXP]),
            Item("key-rsa-alias-pub1", DataType::KEY_RSA_PUBLIC,   policy[NO_PASS][NO_EXP])
    }},
    { Group::KEY_PAIR_RSA, {
            Item("key-rsa-alias-prv2", DataType::KEY_RSA_PRIVATE,  policy[NO_PASS][EXP]),
            Item("key-rsa-alias-pub2", DataType::KEY_RSA_PUBLIC,   policy[NO_PASS][EXP]),
    }},
    { Group::KEY_PAIR_RSA, {
            Item("key-rsa-alias-prv3", DataType::KEY_RSA_PRIVATE,  policy[PASS][NO_EXP]),
            Item("key-rsa-alias-pub3", DataType::KEY_RSA_PUBLIC,   policy[PASS][NO_EXP]),
    }},
    { Group::KEY_PAIR_RSA, {
            Item("key-rsa-alias-prv4", DataType::KEY_RSA_PRIVATE,  policy[PASS][EXP]),
            Item("key-rsa-alias-pub4", DataType::KEY_RSA_PUBLIC,   policy[PASS][EXP]),
    }},
    // different policies
    { Group::KEY_PAIR_RSA, {
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



struct FdCloser {
    void operator()(int* fd) {
        if(fd)
            close(*fd);
    }
};

typedef std::unique_ptr<int, FdCloser> FdPtr;

void restoreFile(const string& filename) {
    string sourcePath = "/usr/share/ckm-db-test/" + filename;
    string targetPath = "/opt/data/ckm/" + filename;

    int ret;

    int sourceFd = TEMP_FAILURE_RETRY(open(sourcePath.c_str(), O_RDONLY));
    BOOST_REQUIRE_MESSAGE(sourceFd > 0, "Opening " << sourcePath << " failed.");

    FdPtr sourceFdPtr(&sourceFd);

    int targetFd = TEMP_FAILURE_RETRY(creat(targetPath.c_str(), 666));
    BOOST_REQUIRE_MESSAGE(targetFd > 0, "Creating " << targetPath << " failed.");

    FdPtr targetFdPtr(&targetFd);

    struct stat sourceStat;
    ret = fstat(sourceFd, &sourceStat);
    BOOST_REQUIRE_MESSAGE(ret != -1, "fstat() failed: " << ret);

    ret = sendfile(targetFd, sourceFd, 0, sourceStat.st_size);
    BOOST_REQUIRE_MESSAGE(ret != -1, "sendfile failed: " << ret);

    ret = fsync(targetFd);
    BOOST_REQUIRE_MESSAGE(ret != -1, "fsync failed: " << ret);
}

void generateRandom(size_t random_bytes, unsigned char *output)
{
    if(random_bytes<=0 || !output)
        throw runtime_error("Invalid param");

    std::ifstream is("/dev/urandom", std::ifstream::binary);
    if(!is)
        throw runtime_error("Failed to read /dev/urandom");
    is.read(reinterpret_cast<char*>(output), random_bytes);
    if(static_cast<std::streamsize>(random_bytes) != is.gcount())
        throw runtime_error("Not enough bytes read from /dev/urandom");
}

RawBuffer createRandomBuffer(size_t random_bytes)
{
    RawBuffer buffer(random_bytes);
    generateRandom(buffer.size(), buffer.data());
    return buffer;
}
} // namespace anonymous


SchemeTest::SchemeTest() : m_userChanged(false), m_directAccessEnabled(false) {
    m_control = Control::create();
    m_mgr = Manager::create();
    initOpenSsl();

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

void SchemeTest::RemoveUserData() {
    if(CKM_API_SUCCESS != m_control->lockUserKey(UID))
        throw runtime_error("lockUserKey failed");

    if(CKM_API_SUCCESS != m_control->removeUserData(UID))
        throw runtime_error("removeUserData failed");
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
        case Group::KEY_PAIR_RSA:
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

void SchemeTest::ReadAll(bool useWrongPass) {
    SwitchToUser();

    for(const auto& g:GROUPS) {
        for(const auto& i:g.items) {
            int ret;
            Password pass = i.policy.password;
            if(useWrongPass) {
                if(pass.empty())
                    pass = TEST_PASS;
                else
                    pass = Password();
            }

            switch (i.type) {
            case DataType::BINARY_DATA:
            {
                RawBuffer receivedData;
                ret = m_mgr->getData(i.alias, pass, receivedData);
                BOOST_REQUIRE_MESSAGE(useWrongPass || receivedData == TEST_DATA,
                                      "Received data is different for " << i.alias);
                break;
            }

            case DataType::KEY_AES:
            case DataType::KEY_RSA_PRIVATE:
            case DataType::KEY_RSA_PUBLIC:
            {
                KeyShPtr receivedKey;
                ret = m_mgr->getKey(i.alias, pass, receivedKey);
                break;
            }

            case DataType::CERTIFICATE:
            {
                CertificateShPtr receivedCert;
                ret = m_mgr->getCertificate(i.alias, pass, receivedCert);
                break;
            }

            case DataType::CHAIN_CERT_0: // pkcs
            {
                PKCS12ShPtr pkcs;
                ret = m_mgr->getPKCS12(i.alias, pass, pass, pkcs);
                break;
            }

            default:
                BOOST_FAIL("Unsupported data type " << i.type);
            }

            if(i.policy.extractable) {
                if(useWrongPass)
                    BOOST_REQUIRE_MESSAGE(ret == CKM_API_ERROR_AUTHENTICATION_FAILED,
                                          "Reading item " << i.alias << " should fail with " <<
                                          CKM_API_ERROR_AUTHENTICATION_FAILED << " got: " << ret);
                else
                    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS, "Reading item " << i.alias <<
                                          " failed with " << ret);
            }
            else
                BOOST_REQUIRE_MESSAGE(ret == CKM_API_ERROR_NOT_EXPORTABLE, "Item " << i.alias <<
                                      " should not be exportable");
        }
    }
}

void SchemeTest::SignVerify() {
    SwitchToUser();

    for(const auto& g:GROUPS) {
        if(g.type == Group::KEY_PAIR_RSA) {
            BOOST_REQUIRE_MESSAGE(g.items.size() == 2, "Wrong number of keys");
            BOOST_REQUIRE_MESSAGE(g.items[0].type == DataType::KEY_RSA_PRIVATE &&
                                  g.items[1].type == DataType::KEY_RSA_PUBLIC, "Wrong key");

            SignVerifyItem(g.items[0], g.items[1]);
        } else {
            for(const auto& i:g.items) {
                switch (i.type) {
                case DataType::CHAIN_CERT_0:
                    SignVerifyItem(i, i);
                    break;

                default:
                    break;
                }
            }
        }
    }
}

void SchemeTest::EncryptDecrypt() {
    SwitchToUser();

    for(const auto& g:GROUPS) {
        if(g.type == Group::KEY_PAIR_RSA) {
            BOOST_REQUIRE_MESSAGE(g.items.size() == 2, "Wrong number of keys");
            BOOST_REQUIRE_MESSAGE(g.items[0].type == DataType::KEY_RSA_PRIVATE &&
                                  g.items[1].type == DataType::KEY_RSA_PUBLIC, "Wrong key");

            EncryptDecryptItem(g.items[0], g.items[1]);
        } else {
            for(const auto& i:g.items) {
                switch (i.type) {
                case DataType::KEY_AES:
                    EncryptDecryptItem(i);
                    break;

                case DataType::CHAIN_CERT_0:
                    EncryptDecryptItem(i, i);
                    break;

                default:
                    break;
                }
            }
        }
    }
}

void SchemeTest::CreateChain() {
    SwitchToUser();

    for(const auto& g:GROUPS) {
        if(g.type == Group::CERT_CHAIN) {
            BOOST_REQUIRE_MESSAGE(g.items.size() == CHAIN_SIZE, "Not enough certificates");
            for(const auto& c:g.items)
                BOOST_REQUIRE_MESSAGE(c.type == DataType::CERTIFICATE, "Wrong item type");
            Items trusted(CHAIN_SIZE-1);
            std::copy(g.items.begin(), g.items.begin() + CHAIN_SIZE-1, trusted.begin());

            // last one is ee (leaf)
            CreateChainItem(g.items.back(), trusted);
        } else {
            for(const auto& i:g.items) {
                if(i.type == DataType::CHAIN_CERT_0) // PKCS
                    CreateChainItem(i, { i });
            }
        }
    }
}

void SchemeTest::RemoveAll() {
    SwitchToUser();

    for(const auto& g:GROUPS) {
        for(const auto& i:g.items) {
            int ret = m_mgr->removeAlias(i.alias);
            BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS,
                                  "removeAlias() failed with " << ret << " for " << i.alias);
        }
    }
}
size_t SchemeTest::CountObjects() {
    EnableDirectDbAccess();

    size_t ret = 0;
    for(const auto& g:GROUPS) {
        for(const auto& i:g.items) {
            DB::RowVector rows;
            // it is assumed that aliases are different
            m_db->getRows(i.alias, DB_LABEL, DataType::DB_FIRST, DataType::DB_LAST, rows);
            ret += rows.size();
        }
    }
    return ret;
}

void SchemeTest::RestoreDb() {
    restoreFile("key-7654");
    restoreFile("db-key-7654");
    restoreFile("db-7654");
    m_db.reset();
    m_directAccessEnabled = false;
}

void SchemeTest::CheckSchemeVersion(const ItemFilter& filter, int version) {
    EnableDirectDbAccess();

    for(const auto& g:GROUPS) {
        for(const auto& i:g.items) {
            if(!filter.Matches(i))
                continue;

            DB::RowVector rows;
            m_db->getRows(i.alias, DB_LABEL, filter.typeFrom, filter.typeTo, rows);
            BOOST_REQUIRE_MESSAGE(rows.size() > 0, "No rows found for " << i.alias);
            for(const auto& r : rows) {
                BOOST_REQUIRE_MESSAGE(
                        (r.encryptionScheme >> ENC_SCHEME_OFFSET) == version,
                        "Wrong encryption scheme for " << i.alias << ". Expected " << version <<
                        " got: " << (r.encryptionScheme >> ENC_SCHEME_OFFSET));
            }
        }
    }
}

void SchemeTest::EnableDirectDbAccess() {
    SwitchToRoot();

    if(m_directAccessEnabled)
        return;

    // direct access to db
    FileSystem fs(UID);
    auto wrappedDKEK = fs.getDKEK();
    auto keyProvider = KeyProvider(wrappedDKEK, DBPASS);

    auto wrappedDatabaseDEK = fs.getDBDEK();
    RawBuffer key = keyProvider.getPureDEK(wrappedDatabaseDEK);

    m_db.reset(new DB::Crypto(fs.getDBPath(), key));
    m_directAccessEnabled = true;
}

void SchemeTest::SignVerifyItem(const Item& itemPrv, const Item& itemPub) {
    int ret;
    KeyShPtr receivedKey;
    RawBuffer signature;
    // create/verify signature
    ret = m_mgr->createSignature(itemPrv.alias,
                                 itemPrv.policy.password,
                                 TEST_DATA,
                                 HashAlgorithm::SHA512,
                                 RSAPaddingAlgorithm::X931,
                                 signature);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS, "createSignature() failed with " << ret <<
                          " for " << itemPrv.alias);
    ret = m_mgr->verifySignature(itemPub.alias,
                                 itemPub.policy.password,
                                 TEST_DATA,
                                 signature,
                                 HashAlgorithm::SHA512,
                                 RSAPaddingAlgorithm::X931);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS, "verifySignature() failed with " << ret <<
                          " for " << itemPub.alias);

}

void SchemeTest::EncryptDecryptItem(const Item& item) {
    CryptoAlgorithm algo;
    RawBuffer iv = createRandomBuffer(IV_LEN);
    RawBuffer encrypted, decrypted;
    int ret;

    algo.setParam(ParamName::ALGO_TYPE, AlgoType::AES_GCM);
    algo.setParam(ParamName::ED_IV, iv);

    ret = m_mgr->encrypt(algo, item.alias, item.policy.password, TEST_DATA, encrypted);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS, "encrypt() failed iwth " << ret << " for " <<
                          item.alias);

    ret = m_mgr->decrypt(algo, item.alias, item.policy.password, encrypted, decrypted);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS, "decrypt() failed iwth " << ret << " for " <<
                          item.alias);

    BOOST_REQUIRE_MESSAGE(decrypted == TEST_DATA, "Decrypted data not equal to original");
}

void SchemeTest::EncryptDecryptItem(const Item& itemPrv, const Item& itemPub) {
    CryptoAlgorithm algo;
    RawBuffer encrypted, decrypted;
    int ret;

    algo.setParam(ParamName::ALGO_TYPE, AlgoType::RSA_OAEP);

    ret = m_mgr->encrypt(algo, itemPub.alias, itemPub.policy.password, TEST_DATA, encrypted);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS, "encrypt() failed iwth " << ret << " for " <<
                          itemPub.alias);

    ret = m_mgr->decrypt(algo, itemPrv.alias, itemPrv.policy.password, encrypted, decrypted);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS, "decrypt() failed iwth " << ret << " for " <<
                          itemPrv.alias);

    BOOST_REQUIRE_MESSAGE(decrypted == TEST_DATA, "Decrypted data not equal to original");
}

void SchemeTest::CreateChainItem(const Item& leaf, const Items& certs) {
    CertificateShPtrVector chain;
    AliasVector trusted;

    if(!leaf.policy.extractable || !leaf.policy.password.empty())
        return;

    for(const auto& i : certs) {
        if(!i.policy.extractable || !i.policy.password.empty())
            return;
        trusted.push_back(i.alias);
    }

    CertificateShPtr leafCrt;
    int ret = m_mgr->getCertificate(leaf.alias, leaf.policy.password, leafCrt);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS,
                          "getCertificate failed with " << ret << " for " <<
                          leaf.alias);

    ret = m_mgr->getCertificateChain(leafCrt, AliasVector(), trusted, false, chain);
    BOOST_REQUIRE_MESSAGE(ret == CKM_API_SUCCESS,
                          "getCertificateChain() failed with " << ret);
    BOOST_REQUIRE_MESSAGE(chain.size() == CHAIN_LEN, "Wrong chain length: " << chain.size());
}
