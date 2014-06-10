#pragma once
#include <string>
#include <ckm/ckm-type.h>
#include <boost/test/unit_test_log.hpp>
#include <boost/test/results_reporter.hpp>

struct TestConfig {
    TestConfig() {
        boost::unit_test::unit_test_log.set_threshold_level( boost::unit_test::log_test_units);
        boost::unit_test::results_reporter::set_level(boost::unit_test::SHORT_REPORT);
    }
    ~TestConfig(){}
};

CKM::RawBuffer createDefaultPass();
CKM::RawBuffer createBigBlob(std::size_t size);

const CKM::RawBuffer defaultPass = createDefaultPass();
const std::string pattern =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const std::size_t RAW_PASS_SIZE = 32;
const std::size_t HEX_PASS_SIZE = RAW_PASS_SIZE * 2;


std::string rawToHexString(const std::vector<unsigned char> &raw);
