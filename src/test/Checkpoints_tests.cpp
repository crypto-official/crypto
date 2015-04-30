//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "../checkpoints.h"
#include "../util.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    uint256 p24200 = uint256("0xd7ed819858011474c8b0cae4ad0b9bdbb745becc4c386bc22d1220cc5a4d1787");
    uint256 p84065 = uint256("0xa904170a5a98109b2909379d9bc03ef97a6b44d5dafbc9084b8699b0cba5aa98");
    BOOST_CHECK(Checkpoints::CheckBlock(24200, p24200));
    BOOST_CHECK(Checkpoints::CheckBlock(84065, p84065));


    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckBlock(24200, p84065));
    BOOST_CHECK(!Checkpoints::CheckBlock(84065, p24200));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckBlock(24200+1, p84065));
    BOOST_CHECK(Checkpoints::CheckBlock(84065+1, p24200));

    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 84065);
}

BOOST_AUTO_TEST_SUITE_END()
