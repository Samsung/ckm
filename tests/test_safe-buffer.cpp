#include <boost/test/unit_test.hpp>

#include <test_common.h>

#include <ckm/ckm-raw-buffer.h>

BOOST_GLOBAL_FIXTURE(TestConfig)

using namespace CKM;

namespace {
    const RawBuffer::size_type LEN = 10;

    struct Item
    {
        Item(size_t a) : mA(a) {}
        ~Item() {}

        size_t mA;
    };
} // namespace anonymous

BOOST_AUTO_TEST_SUITE(SAFE_BUFFER_TEST)

/*
 * Test for SafeBuffer. Checks if memory occupied by the buffer is wiped after
 * it's deleted
 */
BOOST_AUTO_TEST_CASE(SafeBufferTest_uc) {
    const unsigned char* data = NULL;
    RawBuffer::size_type i = 0;
    {
        RawBuffer buffer;
        for (i=0;i<LEN;++i)
            buffer.push_back(i);

        data = buffer.data();

        for (i=0;i<LEN;++i)
            BOOST_CHECK(data[i] == i);
    }
    for (i=0;i<LEN;++i)
        BOOST_CHECK(data[i] == 0);
}

BOOST_AUTO_TEST_CASE(SafeBufferTest_item) {
    const unsigned char* data = NULL;
    RawBuffer::size_type i = 0;
    {
        SafeBuffer<Item>::Type buffer;
        for (i=0;i<LEN;++i)
            buffer.push_back(i);

        for (i=0;i<LEN;++i) {
            BOOST_CHECK(buffer[i].mA == i);
        }

        data = reinterpret_cast<unsigned char*>(buffer.data());
    }
    for (i=0;i<LEN*sizeof(Item);++i)
        BOOST_CHECK(data[i] == 0);
}

BOOST_AUTO_TEST_SUITE_END()
