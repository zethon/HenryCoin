#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nlohmann/json.hpp>

#include "../src/CryptoUtils.h"

namespace nl = nlohmann;
namespace data = boost::unit_test::data;

using namespace std::string_literals;

BOOST_AUTO_TEST_SUITE(merkleroot)

BOOST_AUTO_TEST_CASE(GetAddressLedgerTest)
{
    auto retval = ash::crypto::SHA256Int("This is a test");
    BOOST_TEST(retval == 0);
}

BOOST_AUTO_TEST_SUITE_END() // merkleroot