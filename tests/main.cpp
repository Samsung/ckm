/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       main.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <key-provider.h>
#include <boost/test/unit_test.hpp>
#include <boost/test/unit_test_log.hpp>
#include <boost/test/results_reporter.hpp>
#include <colour_log_formatter.h>
#include <dpl/log/log.h>

struct TestConfig {
    TestConfig() {
        boost::unit_test::unit_test_log.set_threshold_level( boost::unit_test::log_test_units);
        boost::unit_test::results_reporter::set_level(boost::unit_test::SHORT_REPORT);
        boost::unit_test::unit_test_log.set_formatter(new CKM::colour_log_formatter);
    }
    ~TestConfig(){
    }
};

bool isLibInitialized = false;

struct KeyProviderLib {
    KeyProviderLib() {
        Try {
            CKM::KeyProvider::initializeLibrary();
            isLibInitialized = true;
        }
        Catch (CKM::Exception) {
            std::cout << "Library initialization failed!" << std::endl;
        }
    }
    ~KeyProviderLib() {
        Try { CKM::KeyProvider::closeLibrary(); }
        Catch (CKM::Exception) {
            std::cout << "Library deinitialization failed!" << std::endl;
        }
    }
};

struct LogSetup {
    LogSetup() {
        CKM::Singleton<CKM::Log::LogSystem>::Instance().SetTag("CKM_INTERNAL_TESTS");
    }
    ~LogSetup() {}
};

BOOST_GLOBAL_FIXTURE(KeyProviderLib)
BOOST_GLOBAL_FIXTURE(TestConfig)
BOOST_GLOBAL_FIXTURE(LogSetup)

