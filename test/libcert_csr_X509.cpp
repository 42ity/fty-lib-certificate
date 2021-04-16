#include <catch2/catch.hpp>
#include "libcert_csr_X509.h"
#include "libcert_keys.h"

// color output definition for test function
#define ANSI_COLOR_RED   "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

#include <iostream>
#include <vector>

TEST_CASE("libcert_csr_x509_test"){
    using namespace fty;

    std::vector<std::pair<std::string, bool>> testsResults;

    printf(" * libcert_csr_x509: ");

    std::string testNumber;
    std::string testName;

    // Next test
    testNumber = "1.1";
    testName   = "Create CSR-> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // Do the test here. If error throw expections

            Keys keys = Keys::generateRSA(2048);

            CertificateConfig config;

            config.setVersion(3);
            config.setValidFrom(1571840469);
            config.setValidTo(1603462869);
            config.setCountry("CZ");
            config.setState("Praha");
            config.setLocality("Praha");
            config.setOrganization("Eaton");
            config.setOrganizationUnit("DPQ");
            config.setCommonName("test-certificate");
            config.setEmail("MauroGuerrera@eaton.com");
            config.setIpList({"192.168.0.1", "10.22.45.52"});
            config.setDnsList({"myTest.eaton.com"});

            CsrX509 csr = CsrX509::generateCsr(keys, config);

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
    testName   = "Create CSR-> bad case (empty configuration)";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // Do the test here. If error throw expections

            Keys keys = Keys::generateRSA(2048);

            CertificateConfig config;

            CsrX509 csr = CsrX509::generateCsr(keys, config);

            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
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
    testName   = "Check exported key is equal to the one used to sign-> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        try {
            // Do the test here. If error throw expections

            Keys keys = Keys::generateRSA(2048);

            CertificateConfig config;

            config.setVersion(3);
            config.setValidFrom(1571840469);
            config.setValidTo(1603462869);
            config.setCountry("CZ");
            config.setState("Praha");
            config.setLocality("Praha");
            config.setOrganization("Eaton");
            config.setOrganizationUnit("DPQ");
            config.setCommonName("test-certificate");
            config.setEmail("MauroGuerrera@eaton.com");
            config.setIpList({"192.168.0.1", "10.22.45.52"});
            config.setDnsList({"myTest.eaton.com"});

            CsrX509 csr = CsrX509::generateCsr(keys, config);

            if (keys.getPublicKey() != csr.getPublicKey()) {
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
    testName   = "Check CSR import-> success case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        std::string goodPem =
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            "MIIDHjCCAgYCAQIwgYgxCzAJBgNVBAYTAkNaMQ4wDAYDVQQIDAVQcmFoYTEOMAwG\n"
            "A1UEBwwFUHJhaGExDjAMBgNVBAoMBUVhdG9uMQwwCgYDVQQLDANEUFExGTAXBgNV\n"
            "BAMMEHRlc3QtY2VydGlmaWNhdGUxIDAeBgNVBAsMF01hdXJvR3VlcnJlcmFAZWF0\n"
            "b24uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApNVpp+dMHQ8Y\n"
            "sgv/ISFIcMqRXFi4p3GbGycLAJYCxGjlOPhtsO3lkU4Zdl+0JnQxLQm8rcQKMij2\n"
            "i9Y1gZswg8TlKIo7c5MvD2D7WMri/HdFzdZTr7n0zEU/78S+U+bJJvhNQ1mn4zDx\n"
            "NUuRal8eLOjgrLYezCWrDRsydbfclP6hQCqi9DYaYPjPofHfG1CIsypgThZkVHtn\n"
            "1p4eouchJ1sbH6sckauVR+BXVMp5OoasREYraoq6yEDOYHtQCfNbYHTRdfsjRJUz\n"
            "XIZNcx2jVUrgg7NF/Nav72YF5ynnZ11PNl6uuC54l2rei3aB5ea+xoBRaQvJV/uI\n"
            "W0VjRYXWkwIDAQABoFAwTgYJKoZIhvcNAQkOMUEwPzAPBgNVHREECDAGhwTAqAAB\n"
            "MA8GA1UdEQQIMAaHBAoWLTQwGwYDVR0RBBQwEoIQbXlUZXN0LmVhdG9uLmNvbTAN\n"
            "BgkqhkiG9w0BAQsFAAOCAQEAAud1EW5a3jYj4SsvF7uuOjwu428q/lc3o+BtD0wU\n"
            "0uOVRVbXk8DjxVYGpCHuFKKJKv1h6sgKE+wKpVjChjJCjI5hzNstfDjaiPnG0Px9\n"
            "RcRqytpBnsdH4wnQT71e1rGTLbj0hWqEcz6idnrr9DWSAWEMNGG5EJA2k/LylCzL\n"
            "hjeIv9mSKoTX3Cuxr7eoTSqJUJTyXUSN9guFNtp5461XAZE8zTgavOAcGQBBgjTx\n"
            "rgYyBp8BAGFaCRnUkirk7jFjVOiTlXxs03yS08BxekckYHcae2MkOx+P0sw17MLg\n"
            "PqOk8QEy6VWMmJa/6rjW+fJV8CTF93n6ganecVVEmoW1Jw==\n"
            "-----END CERTIFICATE REQUEST-----\n";

        try {
            // Do the test here. If error throw expections

            CsrX509 csr(goodPem);

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
    testName   = "Check CSR import-> bad case";
    printf(
        "\n----------------------------------------------------------------"
        "-------\n");
    {
        printf(" *=>  Test #%s %s\n", testNumber.c_str(), testName.c_str());

        std::string badPem =
            "-----BEGIN REQUEST-----\n"
            "MIIDHjCCAgYCAQIwgYgxCzAJBgNVBAYTAkNaMQ4wDAYDVQQIDAVQcmFoYTEOMAwG\n"
            "A1UEBwwFUHJhaGExDjAMBgNVBAoMBUVhdG9uMQwwCgYDVQQLDANEUFExGTAXBgNV\n"
            "BAMMEHRlc3QtY2VydGlmaWNhdGUxIDAeBgNVBAsMF01hdXJvR3VlcnJlcmFAZWF0\n"
            "b24uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApNVpp+dMHQ8Y\n"
            "sgv/ISFIcMqRXFi4p3GbGycLAJYCxGjlOPhtsO3lkU4Zdl+0JnQxLQm8rcQKMij2\n"
            "i9Y1gZswg8TlKIo7c5MvD2D7WMri/HdFzdZTr7n0zEU/78S+U+bJJvhNQ1mn4zDx\n"
            "NUuRal8eLOjgrLYezCWrDRsydbfclP6hQCqi9DYaYPjPofHfG1CIsypgThZkVHtn\n"
            "1p4eouchJ1sbH6sckauVR+BXVMp5OoasREYraoq6yEDOYHtQCfNbYHTRdfsjRJUz\n"
            "XIZNcx2jVUrgg7NF/Nav72YF5ynnZ11PNl6uuC54l2rei3aB5ea+xoBRaQvJV/uI\n"
            "W0VjRYXWkwIDAQABoFAwTgYJKoZIhvcNAQkOMUEwPzAPBgNVHREECDAGhwTAqAAB\n"
            "MA8GA1UdEQQIMAaHBAoWLTQwGwYDVR0RBBQwEoIQbXlUZXN0LmVhdG9uLmNvbTAN\n"
            "BgkqhkiG9w0BAQsFAAOCAQEAAud1EW5a3jYj4SsvF7uuOjwu428q/lc3o+BtD0wU\n"
            "0uOVRVbXk8DjxVYGpCHuFKKJKv1h6sgKE+wKpVjChjJCjI5hzNstfDjaiPnG0Px9\n"
            "RcRqytpBnsdH4wnQT71e1rGTLbj0hWqEcz6idnrr9DWSAWEMNGG5EJA2k/LylCzL\n"
            "hjeIv9mSKoTX3Cuxr7eoTSqJUJTyXUSN9guFNtp5461XAZE8zTgavOAcGQBBgjTx\n"
            "rgYyBp8BAGFaCRnUkirk7jFjVOiTlXxs03yS08BxekckYHcae2MkOx+P0sw17MLg\n"
            "PqOk8QEy6VWMmJa/6rjW+fJV8CTF93n6ganecVVEmoW1Jw==\n"
            "-----END REQUEST-----\n";

        try {
            // Do the test here. If error throw expections

            CsrX509 cert(badPem);

            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back(" Test #" + testNumber + " " + testName, true);
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


    // collect results

    printf("\n-----------------------------------------------------------------------\n");

    uint32_t testsPassed = 0;
    uint32_t testsFailed = 0;


    printf("\tSummary tests from libcert_csr_x509\n");
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

    printf("OK\n");
    REQUIRE(true);
}
