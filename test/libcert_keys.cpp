#include <catch2/catch.hpp>
#include "libcert_keys.h"

TEST_CASE("libcert_keys_test") {
    using namespace fty;

    std::vector<std::pair<std::string, bool>> testsResults;

    {
        std::string goodPrivateKey =
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIL7VJ+0/m9Ue0L7k4zb6ocTm5e4FTdIYrK+A10nwKKt5oAoGCCqGSM49\n"
            "AwEHoUQDQgAE/YGxBElUytMJZyd7Waifmc6kfs8N88oCoGFrHk1BQf05gqWUADDw\n"
            "dEYnwoyPc82tWrizPTrsDwA5afpKo5Mxsw==\n"
            "-----END EC PRIVATE KEY-----\n";

        try {
            // Do the test here. If error throw expections
            Keys pk_ec = Keys(goodPrivateKey);
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        std::string badPrivateKey =
            "-----BEGIN EC KEY-----\n"
            "MHcCAQEEIL7VJ+0/m9Ue0L7k4zb6ocTm5e4FTdIYrK+A10nwKKt5oAoGCCqGSM49\n"
            "AwEHoUQDQgAE/YGxBElUytMJZyd7Waifmc6kfs8N88oCoGFrHk1BQf05gqWUADDw\n"
            "dEYnwoyPc82tWrizPTrsDwA5afpKo5Mxsw==\n"
            "-----END EC PRIVATE KEY-----\n";

        try {
            // do the test here
            Keys pk_ec = Keys(badPrivateKey);

            // if the error works we should not go here.
            throw std::logic_error("The function succeed");
        } catch (const std::runtime_error& e) {
            // expected error
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        try {
            // do the test here
            Keys pk_ec = Keys("---BAD STUFF---");

            // if the error works we should not go here.
            throw std::logic_error("The function succeed");
        } catch (const std::runtime_error& e) {
            // expected error
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        try {
            // Do the test here. If error throw expections
            Keys pk_ec = Keys::generateRSA(512);
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        try {
            // Do the test here. If error throw expections
            Keys        pk1     = Keys::generateRSA(512);
            std::string pk1_pem = pk1.getPem();

            Keys        pk2     = Keys(pk1_pem);
            std::string pk2_pem = pk2.getPem();

            if (pk1_pem != pk2_pem) {
                throw std::runtime_error("PEM keys mismatch");
            }
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        try {
            // Do the test here. If error throw expections
            Keys pk_ec = Keys::generateEC(ECKeyType::PRIME256V1);
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        try {
            // Do the test here. If error throw expections
            Keys        pk1     = Keys::generateEC(PRIME256V1);
            std::string pk1_pem = pk1.getPem();

            Keys        pk2     = Keys(pk1_pem);
            std::string pk2_pem = pk2.getPem();

            if (pk1_pem != pk2_pem) {
                throw std::runtime_error("PEM keys mismatch");
            }
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
}
