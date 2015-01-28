#include <vector>

#include <boost/test/unit_test.hpp>
#include <test_common.h>

#include <ckm/ckm-raw-buffer.h>

using namespace CKM;

namespace {

const size_t LEN = 100;

struct Item
{
    Item(size_t a) : mA(a) {}
    ~Item() {}

    bool operator==(const size_t& other) const {
        return mA == other;
    }

    size_t mA;
};

template <typename T>
size_t buffer_erase_test()
{
    typename T::value_type* data = NULL;
    typename T::size_type i = 0;
    {
        T buffer;
        for (i=0;i<LEN;++i)
            buffer.push_back(typename T::value_type(i));

        data = buffer.data();

        for (i=0;i<LEN;++i)
            BOOST_CHECK(data[i] == i);
    }

    /*
     *  operator delete of RawBuffer which is called after buffer memory is erased
     *  (see erase_on_dealloc::deallocate) sometimes leaves garbage in the beginning of that memory.
     *  Therefore the test will be marked as failing only if more than 1/10 of the data matches
     *  original
     */
    size_t cnt = 0;
    for (i=0;i<LEN;++i)
        cnt += (data[i] == i?1:0);

    return cnt;
}

} // namespace anonymous

BOOST_AUTO_TEST_SUITE(SAFE_BUFFER_TEST)

// Tests for SafeBuffer. Checks if memory occupied by the buffer is wiped after it's deleted.

BOOST_AUTO_TEST_CASE(SafeBufferTest_uc_control_group) {
    size_t cnt = buffer_erase_test<std::vector<unsigned char> >();

    BOOST_REQUIRE_MESSAGE(cnt > LEN/2, "Less than 1/2 of data matches the original.");
}

BOOST_AUTO_TEST_CASE(SafeBufferTest_item_control_group) {
    size_t cnt = buffer_erase_test<std::vector<Item> >();

    BOOST_REQUIRE_MESSAGE(cnt > LEN/2, "Less than 1/2 of data matches the original.");
}

BOOST_AUTO_TEST_CASE(SafeBufferTest_uc) {
    size_t cnt = buffer_erase_test<RawBuffer>();

    BOOST_REQUIRE_MESSAGE(cnt <= LEN/10, "More than 1/10 of data matches the original.");
}

BOOST_AUTO_TEST_CASE(SafeBufferTest_item) {
    size_t cnt = buffer_erase_test<SafeBuffer<Item>::Type>();

    BOOST_REQUIRE_MESSAGE(cnt <= LEN/10, "More than 1/10 of data matches the original.");
}

BOOST_AUTO_TEST_SUITE_END()
