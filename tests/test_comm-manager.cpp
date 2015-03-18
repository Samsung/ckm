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
 * @file       test_comm-manager.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>
#include <communication-manager.h>
#include <string>
#include <random>
#include <chrono>

namespace {
struct MessageA {
    MessageA(int ai) : i(ai) {}
    int i;
};

struct MessageB {
    MessageB(char ac) : c(ac) {}
    char c;
};

struct MessageC {
    MessageC(const std::string& astr) : str(astr) {}
    std::string str;
};

struct Listener {
    Listener() : i(0) {}

    void Handle(const MessageA& msg) {
        i = msg.i;
    }

    void Handle(const MessageC& msg) {
        str = msg.str;
    }

    int i;
    std::string str;
};

} // namespace anonymous

BOOST_AUTO_TEST_SUITE(MESSAGE_MANAGER_TEST)

BOOST_AUTO_TEST_CASE(TMM_0010_NoListener) {
    CKM::CommunicationManager<MessageA> mgr;
    //int reci = 0;
    mgr.SendMessage(MessageA(22));
}

BOOST_AUTO_TEST_CASE(TMM_0020_Basic) {
    CKM::CommunicationManager<MessageA> mgr;
    int received = 0;
    mgr.Register<MessageA>([&](const MessageA& msg){ received = msg.i; });
    mgr.SendMessage(MessageA(4));
    BOOST_REQUIRE_MESSAGE(received != 0, "Message not received");
    BOOST_REQUIRE_MESSAGE(received == 4, "Wrong message received i=" << received);
}

BOOST_AUTO_TEST_CASE(TMM_0030_MultipleMessages) {
    CKM::CommunicationManager<MessageA, MessageB> mgr;
    int reci = 0;
    char recc = 0;
    mgr.Register<MessageA>([&](const MessageA& msg){ reci = msg.i; });
    mgr.Register<MessageB>([&](const MessageB& msg){ recc = msg.c; });
    mgr.SendMessage(MessageB('c'));
    BOOST_REQUIRE_MESSAGE(reci == 0, "Unexpected message received");
    BOOST_REQUIRE_MESSAGE(recc != 0, "Message not received");
    BOOST_REQUIRE_MESSAGE(recc == 'c', "Wrong message received c=" << recc);

    mgr.SendMessage(MessageA(42));
    BOOST_REQUIRE_MESSAGE(reci!= 0, "Message not received");
    BOOST_REQUIRE_MESSAGE(reci == 42, "Wrong message received i=" << reci);
    BOOST_REQUIRE_MESSAGE(recc == 'c', "Previous message overwritten c=" << recc);
}

BOOST_AUTO_TEST_CASE(TMM_0040_Listener) {
    CKM::CommunicationManager<MessageA, MessageB, MessageC> mgr;
    Listener l;
    mgr.Register<MessageC>([&](const MessageC& msg){ l.Handle(msg); });
    mgr.Register<MessageA>([&](const MessageA& msg){ l.Handle(msg); });

    mgr.SendMessage(MessageC("lorem ipsum"));
    BOOST_REQUIRE_MESSAGE(l.i == 0, "Unexpected message received");
    BOOST_REQUIRE_MESSAGE(!l.str.empty(), "Message not received");
    BOOST_REQUIRE_MESSAGE(l.str == "lorem ipsum", "Wrong message received c=" << l.str);

    mgr.SendMessage(MessageA(3));
    BOOST_REQUIRE_MESSAGE(l.i!= 0, "Message not received");
    BOOST_REQUIRE_MESSAGE(l.i == 3, "Wrong message received i=" << l.i);
    BOOST_REQUIRE_MESSAGE(l.str == "lorem ipsum", "Previous message overwritten str=" << l.str);
}

BOOST_AUTO_TEST_CASE(TMM_0050_2Listeners) {
    CKM::CommunicationManager<MessageA> mgr;
    bool called[2];
    called[0] = false;
    called[1] = false;
    mgr.Register<MessageA>([&](const MessageA& msg){
        BOOST_REQUIRE_MESSAGE(msg.i == 5, "Unexpected message received i=" << msg.i);
        called[0] = true;
    });
    mgr.Register<MessageA>([&](const MessageA& msg){
        BOOST_REQUIRE_MESSAGE(msg.i == 5, "Unexpected message received i=" << msg.i);
        called[1] = true;
    });

    mgr.SendMessage(MessageA(5));
    BOOST_REQUIRE_MESSAGE(called[0], "First listener not called");
    BOOST_REQUIRE_MESSAGE(called[1], "Second listener not called");
}

BOOST_AUTO_TEST_CASE(TMM_0060_Stress) {
    CKM::CommunicationManager<MessageA, MessageB, MessageC> mgr;

    std::default_random_engine generator(std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<size_t> message_dist(0,2);
    std::uniform_int_distribution<size_t> count_dist(1,10);

    size_t a = 0;
    size_t b = 0;
    size_t c = 0;
    mgr.Register<MessageA>([&](const MessageA& msg) {
        BOOST_REQUIRE_MESSAGE(msg.i == 42, "Wrong message: " << msg.i);
        a++;
    });
    mgr.Register<MessageB>([&](const MessageB& msg) {
        BOOST_REQUIRE_MESSAGE(msg.c == 'c', "Wrong message: " << msg.c);
        b++;
    });
    mgr.Register<MessageC>([&](const MessageC& msg) {
        BOOST_REQUIRE_MESSAGE(msg.str == "lorem ipsum", "Wrong message: " << msg.str);
        c++;
    });

    for (size_t i=0; i < 1000; i++)
    {
        size_t cnt = count_dist(generator);
        for (size_t s = 0; s < cnt; s++) {
            switch(message_dist(generator))
            {
            case 0:
                mgr.SendMessage(MessageA(42));
                a--;
                break;
            case 1:
                mgr.SendMessage(MessageB('c'));
                b--;
                break;
            case 2:
                mgr.SendMessage(MessageC("lorem ipsum"));
                c--;
                break;
            default:
                BOOST_FAIL("Unexpected message type");
            }
        }
    }
    BOOST_REQUIRE_MESSAGE(a == 0, "Unexpected number of MessageA: " << a);
    BOOST_REQUIRE_MESSAGE(b == 0, "Unexpected number of MessageB: " << b);
    BOOST_REQUIRE_MESSAGE(c == 0, "Unexpected number of MessageC: " << c);
}

BOOST_AUTO_TEST_SUITE_END()


