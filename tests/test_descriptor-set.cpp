/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       test_descriptor-set.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <thread>
#include <memory>

#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>

#include <test_common.h>
#include <test_watched-thread.h>

#include <descriptor-set.h>

BOOST_GLOBAL_FIXTURE(TestConfig)

using namespace CKM;

namespace {

const int POLL_TIMEOUT = 8000;
const int POLL_TIMEOUT_SHORT = 1000;

typedef std::unique_ptr<int[], std::function<void(int *)>> PipePtr;

const short POLLALL = std::numeric_limits<short>::max();

void closePipe(int* fd) {
    close(fd[0]);
    close(fd[1]);
}

/*
 * Declares pipe descriptor array
 * Creates pipe and checks for error
 * Wraps pipe in unique_ptr
 */
#define PIPE(fd) \
    int (fd)[2]; \
    BOOST_REQUIRE_MESSAGE(0 == pipe((fd)),"Pipe creation failed: " << strerror(errno)); \
    PipePtr fd##Ptr((fd), closePipe);

void unexpectedCallback(int, short) {
    BOOST_FAIL("Unexpected callback");
}

void readFd(int fd, int expectedFd, short revents) {
    char buf[1];
    BOOST_REQUIRE_MESSAGE(fd == expectedFd, "Unexpected descriptor");
    BOOST_REQUIRE_MESSAGE(revents & POLLIN, "Unexpected event");
    BOOST_REQUIRE_MESSAGE(1 == TEMP_FAILURE_RETRY(read(fd,buf,1)),
                          "Pipe read failed" << strerror(errno));
}

void writeFd(int fd, int expectedFd, short revents) {
    BOOST_REQUIRE_MESSAGE(fd == expectedFd, "Unexpected descriptor");
    BOOST_REQUIRE_MESSAGE(revents & POLLOUT, "Unexpected event");
    BOOST_REQUIRE_MESSAGE(1 == TEMP_FAILURE_RETRY(write(fd,"j",1)),
                          "Pipe writing failed" << strerror(errno));
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(DESCRIPTOR_SET_TEST)

/*
 * Wait on empty descriptor set. Function should return immediately.
 */
BOOST_AUTO_TEST_CASE(T010_Empty) {
    DescriptorSet descriptors;

    BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
}

/*
 * Add and remove (twice) descriptor. Wait on empty set. No callback should be called. wait() should
 * return immediately.
 */
BOOST_AUTO_TEST_CASE(T020_AddRemove) {
    DescriptorSet descriptors;
    descriptors.add(10, POLLALL, unexpectedCallback);
    descriptors.remove(10);
    descriptors.remove(10);

    BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
}

/*
 * Add 2 descriptors and purge all. Wait on empty set. No callback should be called. wait() should
 * return immediately.
 */
BOOST_AUTO_TEST_CASE(T030_AddPurge) {
    DescriptorSet descriptors;
    descriptors.add(10, POLLALL, unexpectedCallback);
    descriptors.add(20, POLLALL, unexpectedCallback);
    descriptors.purge();

    BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
}

/*
 * Add pipe[1] descriptor and wait for write possibility. Provided callback should be called
 * immediately.
 */
BOOST_AUTO_TEST_CASE(T040_Callback) {
    DescriptorSet descriptors;
    bool callback = false;

    PIPE(fd);

    descriptors.add(fd[1],POLLALL, [&callback](int, short revents)
    {
        callback = true;
        BOOST_REQUIRE_MESSAGE(revents & POLLOUT, "Not able to write");
    });

    BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
    BOOST_REQUIRE_MESSAGE(callback, "Callback was not called");
}

/*
 * Add pipe[1] descriptor twice with different callbacks. The first one should be overwritten and
 * shouldn't be called. The second one should be called instead.
 */
BOOST_AUTO_TEST_CASE(T050_DoubleAdd) {
    DescriptorSet descriptors;
    bool callback = false;

    PIPE(fd);

    descriptors.add(fd[1], POLLALL, unexpectedCallback);
    descriptors.add(fd[1], POLLALL, [&callback](int, short revents)
    {
        callback = true;
        BOOST_REQUIRE_MESSAGE(revents & POLLOUT, "Not able to write");
    });

    BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
    BOOST_REQUIRE_MESSAGE(callback, "Callback was not called");
}

/*
 * Add pipe[0] descriptor and wait. Callback should not be called. Instead the 8s timeout should
 * occur and a proper exception should be thrown.
 */
BOOST_AUTO_TEST_CASE(T060_Timeout) {
    DescriptorSet descriptors;

    PIPE(fd);

    descriptors.add(fd[0],POLLALL, unexpectedCallback);

    BOOST_REQUIRE_THROW(descriptors.wait(POLL_TIMEOUT_SHORT), CKM::DescriptorSet::Timeout);
}

/*
 * Create pipe and try to write it. Start thread that will read it.
 */
BOOST_AUTO_TEST_CASE(T070_Write) {
    DescriptorSet descriptors;
    bool callback = false;

    PIPE(fd);

    descriptors.add(fd[1],POLLOUT, [&fd, &callback](int desc, short revents)
    {
        callback = true;
        writeFd(desc, fd[1], revents);
    } );

    {
        auto thread = CreateWatchedThread([fd]
        {
            char buf[1];
            ssize_t tmp = TEMP_FAILURE_RETRY(read(fd[0], buf, 1));
            THREAD_REQUIRE_MESSAGE(tmp == 1, "Pipe reading failed " << strerror(errno));
        });

        BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
    }

    BOOST_REQUIRE_MESSAGE(callback, "Callback not called");
}

/*
 * Create pipe and try to read it. Start thread that will write it.
 */
BOOST_AUTO_TEST_CASE(T080_Read) {
    DescriptorSet descriptors;
    bool callback = false;

    PIPE(fd);

    descriptors.add(fd[0],POLLIN, [&](int desc, short revents)
    {
        callback = true;
        readFd(desc, fd[0], revents);
    } );

    {
        auto thread = CreateWatchedThread([fd]
        {
            ssize_t tmp = TEMP_FAILURE_RETRY(write(fd[1], "j", 1));
            THREAD_REQUIRE_MESSAGE(tmp == 1, "Pipe writing failed " << strerror(errno));
        });

        BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
    }

    BOOST_REQUIRE_MESSAGE(callback, "Callback not called");
}

/*
 * Create two pipes. Try to read first one. Start the thread that writes it. In the callback read
 * the pipe, remove it from the descriptor set and try to write the second pipe. The thread will
 * read it. In second pipe callback remove the second pipe descriptor from the set.
 */
BOOST_AUTO_TEST_CASE(T090_WriteAfterRead) {
    DescriptorSet descriptors;
    bool callback1 = false;
    bool callback2 = false;

    PIPE(fd);
    PIPE(fd2);

    descriptors.add(fd[0],POLLIN, [&](int desc, short revents)
    {
        callback1 = true;
        readFd(desc, fd[0], revents);

        descriptors.remove(desc);
        descriptors.add(fd2[1],POLLOUT, [&](int desc, short revents) {
            callback2 = true;
            writeFd(desc, fd2[1], revents);
            descriptors.remove(desc);
        } );
    } );

    {
        auto thread = CreateWatchedThread([fd,fd2]
        {
            ssize_t tmp = TEMP_FAILURE_RETRY(write(fd[1], "j", 1));
            BOOST_REQUIRE_MESSAGE(tmp == 1, "Pipe writing failed " << strerror(errno));

            char buf[1];
            tmp = TEMP_FAILURE_RETRY(read(fd2[0], buf, 1));
            THREAD_REQUIRE_MESSAGE(tmp == 1, "Pipe reading failed " << strerror(errno));
        });

        BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
        BOOST_REQUIRE_NO_THROW(descriptors.wait(POLL_TIMEOUT));
    }

    BOOST_REQUIRE_MESSAGE(callback1, "First callback not called");
    BOOST_REQUIRE_MESSAGE(callback2, "Second callback not called");
}

BOOST_AUTO_TEST_SUITE_END()
