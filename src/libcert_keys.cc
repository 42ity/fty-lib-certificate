/*  =========================================================================
    libcert_keys - Keys (Public and Private)

    Copyright (C) 2019 - 2020 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    libcert_keys - Keys (Public and Private)
@discuss
@end
*/

#include "fty_lib_certificate_classes.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace fty {
Keys::Keys(const std::string& privateKeyPem)
{
    importPem(privateKeyPem);
}

Keys::Keys(const Keys& key)
{
    importPem(key.getPem());
}

Keys::~Keys()
{
    EVP_PKEY_free(m_evpPkey);
}

std::string Keys::getPem() const
{
    BIO*        bioOut = BIO_new(BIO_s_mem());
    std::string pem;

    PEM_write_bio_PrivateKey(bioOut, m_evpPkey, NULL, NULL, 0, 0, NULL);

    BUF_MEM* bioBuffer;
    BIO_get_mem_ptr(bioOut, &bioBuffer);
    pem = std::string(bioBuffer->data, bioBuffer->length);

    BIO_free(bioOut);

    return pem;
}

PublicKey Keys::getPublicKey() const
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    m_evpPkey->references++;
#else
    EVP_PKEY_up_ref(m_evpPkey);
#endif
    return PublicKey(m_evpPkey);
}

Keys Keys::generateRSA(int bits)
{
    // 1. generate rsa key
    BIGNUM* bne = BN_new();

    if ((BN_set_word(bne, RSA_F4)) != 1) {
        BN_free(bne);
        throw std::runtime_error("Unable to create private key: big number generation failed");
    }

    RSA* rsaKey = RSA_new();

    if ((RSA_generate_key_ex(rsaKey, bits, bne, NULL)) != 1) {
        BN_free(bne);
        RSA_free(rsaKey);
        throw std::runtime_error("Unable to create private key: RSA generation failed");
    }

    BN_free(bne);

    EVP_PKEY* evpPkey = EVP_PKEY_new();

    if ((EVP_PKEY_assign_RSA(evpPkey, rsaKey) == 0)) {
        RSA_free(rsaKey);
        EVP_PKEY_free(evpPkey);
        throw std::runtime_error("Failed to assign RSA key to private key.");
    }

    return Keys(evpPkey);
}

Keys Keys::generateEC(ECKeyType keyType)
{
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(keyType);
    EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

    if (EC_KEY_generate_key(ecKey) == 0) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("Unable to create private key: EC keygen failed");
    }

    EVP_PKEY* evpPkey = EVP_PKEY_new();

    if (EVP_PKEY_assign_EC_KEY(evpPkey, ecKey) == 0) {
        EC_KEY_free(ecKey);
        EVP_PKEY_free(evpPkey);
        throw std::runtime_error("Failed to assign EC key to private key.");
    }

    return Keys(evpPkey);
}

// private constructor
Keys::Keys(EVP_PKEY* evpPkey)
{
    m_evpPkey = evpPkey;

    if (m_evpPkey == NULL) {
        throw std::runtime_error("Impossible to create the private key");
    }
}

void Keys::importPem(const std::string& privateKeyPem)
{
    std::string s(privateKeyPem.c_str());
    BIO*        bio = BIO_new_mem_buf(static_cast<void*>(&s), static_cast<int>(privateKeyPem.length()));

    if (bio == NULL) {
        throw std::runtime_error("Impossible to create the private key");
    }

    m_evpPkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (m_evpPkey == NULL) {
        throw std::runtime_error("Impossible to create the private key");
    }
}

} // namespace fty


//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

// color output definition for test function
#define ANSI_COLOR_RED   "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

void libcert_keys_test(bool /* verbose */)
{
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

        assert(false);
    }
}
