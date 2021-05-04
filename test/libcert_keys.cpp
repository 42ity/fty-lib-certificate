#include <catch2/catch.hpp>
#include "libcert_keys.h"

// color output definition for test function
#define ANSI_COLOR_RED   "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

TEST_CASE("libcert_keys_test") {
    using namespace fty;

    std::vector<std::pair<std::string, bool>> testsResults;

    printf(" ** libcert_test: \n");

    std::string testNumber;
    std::string testName;

    // Next test
    testNumber = "1.1";
    testName   = "Test of Key PEM import-> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        std::string goodPrivateKey =
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIL7VJ+0/m9Ue0L7k4zb6ocTm5e4FTdIYrK+A10nwKKt5oAoGCCqGSM49\n"
            "AwEHoUQDQgAE/YGxBElUytMJZyd7Waifmc6kfs8N88oCoGFrHk1BQf05gqWUADDw\n"
            "dEYnwoyPc82tWrizPTrsDwA5afpKo5Mxsw==\n"
            "-----END EC PRIVATE KEY-----\n";

        try {
            // Do the test here. If error throw expections

            Keys pk_ec = Keys(goodPrivateKey);

            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
        } catch (const std::exception& e) {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n", e.what());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, false);
        }
    }
    printf("OK\n");

    // Next test
    testNumber = "1.2";
    testName   = "Test of Key PEM import-> bad format #1";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

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
            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
        } catch (const std::exception& e) {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n", e.what());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, false);
        }
    }
    printf("OK\n");

    // Next test
    testNumber = "1.3";
    testName   = "Test of Key PEM import-> bad format #2";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // do the test here

            Keys pk_ec = Keys("---BAD STUFF---");

            // if the error works we should not go here.
            throw std::logic_error("The function succeed");
        } catch (const std::runtime_error& e) {
            // expected error
            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
        } catch (const std::exception& e) {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n", e.what());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, false);
        }
    }
    printf("OK\n");

    // Next test
    testNumber = "2.1";
    testName   = "Test of RSA key generation -> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // Do the test here. If error throw expections

            Keys pk_ec = Keys::generateRSA(512);

            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
        } catch (const std::exception& e) {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n", e.what());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, false);
        }
    }
    printf("OK\n");

    // Next test
    testNumber = "2.2";
    testName   = "Test of RSA key PEM export & import-> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // Do the test here. If error throw expections

            Keys        pk1     = Keys::generateRSA(512);
            std::string pk1_pem = pk1.getPem();

            Keys        pk2     = Keys(pk1_pem);
            std::string pk2_pem = pk2.getPem();

            if (pk1_pem != pk2_pem) {
                throw std::runtime_error("PEM keys mismatch");
            }

            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
        } catch (const std::exception& e) {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n", e.what());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, false);
        }
    }
    printf("OK\n");


    // Next test
    testNumber = "3.1";
    testName   = "Test of EC key generation with PRIME256V1 -> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // Do the test here. If error throw expections

            Keys pk_ec = Keys::generateEC(ECKeyType::PRIME256V1);

            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
        } catch (const std::exception& e) {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n", e.what());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, false);
        }
    }
    printf("OK\n");


    // Next test
    testNumber = "3.2";
    testName   = "Test of EC key PEM export & import -> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // Do the test here. If error throw expections

            Keys        pk1     = Keys::generateEC(PRIME256V1);
            std::string pk1_pem = pk1.getPem();

            Keys        pk2     = Keys(pk1_pem);
            std::string pk2_pem = pk2.getPem();

            if (pk1_pem != pk2_pem) {
                throw std::runtime_error("PEM keys mismatch");
            }

            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
        } catch (const std::exception& e) {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n", e.what());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, false);
        }
    }
    printf("OK\n");

    // collect results

    printf("\n-----------------------------------------------------------------------\n");

    uint32_t testsPassed = 0;
    uint32_t testsFailed = 0;


    printf("\tSummary tests from libcert_keys\n");
    for (const auto& result : testsResults) {
        if (result.second) {
            printf(ANSI_COLOR_GREEN "\tOK " ANSI_COLOR_RESET "\t%s\n", result.first.c_str());
            testsPassed++;
        } else {
            printf(ANSI_COLOR_RED "\tNOK" ANSI_COLOR_RESET "\t%s\n", result.first.c_str());
            testsFailed++;
        }
    }

    printf("\n-----------------------------------------------------------------------\n");

    if (testsFailed == 0) {
        printf(ANSI_COLOR_GREEN "\n %i tests passed, everything is ok\n" ANSI_COLOR_RESET "\n", testsPassed);
    } else {
        printf(ANSI_COLOR_RED "\n!!!!!!!! %i/%i tests did not pass !!!!!!!! \n" ANSI_COLOR_RESET "\n", testsFailed,
            (testsPassed + testsFailed));

        REQUIRE(false);
    }
    REQUIRE(true);
}
