#include <catch2/catch.hpp>
#include <iostream>
#include <vector>
#include "libcert_certificate_X509.h"
#include "libcert_keys.h"

TEST_CASE("libcert_certificate_x509_test")
{
    using namespace fty;

    {
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

            CertificateX509 certificate = CertificateX509::selfSignSha256(keys, config);
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        try {
            // Do the test here. If error throw expections

            Keys keys = Keys::generateRSA(2048);

            CertificateConfig config;

            CertificateX509 certificate = CertificateX509::selfSignSha256(keys, config);
        } catch (const std::runtime_error& e) {
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
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

            CertificateX509 certificate = CertificateX509::selfSignSha256(keys, config);

            if (keys.getPublicKey() != certificate.getPublicKey()) {
                throw std::runtime_error("PEM keys mismatch");
            }
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }

    {
        std::string goodPem =
            "-----BEGIN CERTIFICATE-----\n"
            "MIID1jCCAr6gAwIBAgIJALMAxv/ljVRoMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD\n"
            "VQQGEwJDWjEOMAwGA1UECAwFUHJhaGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQK\n"
            "DAVFYXRvbjEMMAoGA1UECwwDRFBRMRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRl\n"
            "MSAwHgYDVQQLDBdNYXVyb0d1ZXJyZXJhQGVhdG9uLmNvbTAeFw0xOTEwMjMxNDIx\n"
            "MDlaFw0yMDEwMjMxNDIxMDlaMIGIMQswCQYDVQQGEwJDWjEOMAwGA1UECAwFUHJh\n"
            "aGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQKDAVFYXRvbjEMMAoGA1UECwwDRFBR\n"
            "MRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRlMSAwHgYDVQQLDBdNYXVyb0d1ZXJy\n"
            "ZXJhQGVhdG9uLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7T\n"
            "GSq1qrr16SP4RfDePWds6SZMRr+ovTis+Iub88tst+hQOZRrCby81cyfYh39dqpY\n"
            "mU1K1a1+fppD7Ci2unZAvjoKQEQzRA+1ie7Yo5fRdiXw7DSFDzQ9VypGCvQaWe20\n"
            "kLpv8io34oJKen1Qa5+oMfthivQCXZ1jW3ulRW7MzgtmZyO1hZyS20L5uvDytnG1\n"
            "B0q+8l32YaLJW1W/Swy336+5sMzLbdomMPgLnz3QLBGDENwHH6Fj5OGmejG94KSP\n"
            "7mjambagdKZjYZxrsKE6CzY2RjVfCGgf6IqczCN5pxl6F4TPzjD/HqZ4gGSajVEB\n"
            "NlEj6ZvOuLk2x0553csCAwEAAaNBMD8wDwYDVR0RBAgwBocEwKgAATAPBgNVHREE\n"
            "CDAGhwQKFi00MBsGA1UdEQQUMBKCEG15VGVzdC5lYXRvbi5jb20wDQYJKoZIhvcN\n"
            "AQELBQADggEBAFs5cQEaNDHdfBIeDMrfHN27sLbNv3Zb6URY7TMjCeRgHSI1wt/o\n"
            "mEYL1RjHCqiv8HAWQ9ujXx5Ec3Ou4xo1G/m/FmyqTYonGI8dfMMuk1b4U3LLglbg\n"
            "gi/HP4+ThknFRd6f3CoAqCqbumhI5GpvfzE+fjyZlvgE4QFfRq/zxD3rEDmwMHy9\n"
            "QMPtFEvIfEJBQ+YRDSYE0uEClp+brvInyxMKSRxPhGdS5xRgnvlCMobz7riPTTW4\n"
            "cRPZdzLsbgvV5jjL+QCrbViyhiGwsczGMpiKzC6vblXNRyIIthqg5kOXdCZKAEN+\n"
            "zAgPfwIMGJbzkbie0ge5DaxUXq6UTZOgNzw=\n"
            "-----END CERTIFICATE-----\n";

        try {
            // Do the test here. If error throw expections
            CertificateX509 cert(goodPem);
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
    {
        std::string badPem =
            "-----BEGIN-----\n"
            "MIID1jCCAr6gAwIBAgIJALMAxv/ljVRoMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD\n"
            "VQQGEwJDWjEOMAwGA1UECAwFUHJhaGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQK\n"
            "DAVFYXRvbjEMMAoGA1UECwwDRFBRMRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRl\n"
            "MSAwHgYDVQQLDBdNYXVyb0d1ZXJyZXJhQGVhdG9uLmNvbTAeFw0xOTEwMjMxNDIx\n"
            "MDlaFw0yMDEwMjMxNDIxMDlaMIGIMQswCQYDVQQGEwJDWjEOMAwGA1UECAwFUHJh\n"
            "aGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQKDAVFYXRvbjEMMAoGA1UECwwDRFBR\n"
            "MRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRlMSAwHgYDVQQLDBdNYXVyb0d1ZXJy\n"
            "ZXJhQGVhdG9uLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7T\n"
            "GSq1qrr16SP4RfDePWds6SZMRr+ovTis+Iub88tst+hQOZRrCby81cyfYh39dqpY\n"
            "mU1K1a1+fppD7Ci2unZAvjoKQEQzRA+1ie7Yo5fRdiXw7DSFDzQ9VypGCvQaWe20\n"
            "kLpv8io34oJKen1Qa5+oMfthivQCXZ1jW3ulRW7MzgtmZyO1hZyS20L5uvDytnG1\n"
            "B0q+8l32YaLJW1W/Swy336+5sMzLbdomMPgLnz3QLBGDENwHH6Fj5OGmejG94KSP\n"
            "7mjambagdKZjYZxrsKE6CzY2RjVfCGgf6IqczCN5pxl6F4TPzjD/HqZ4gGSajVEB\n"
            "NlEj6ZvOuLk2x0553csCAwEAAaNBMD8wDwYDVR0RBAgwBocEwKgAATAPBgNVHREE\n"
            "CDAGhwQKFi00MBsGA1UdEQQUMBKCEG15VGVzdC5lYXRvbi5jb20wDQYJKoZIhvcN\n"
            "AQELBQADggEBAFs5cQEaNDHdfBIeDMrfHN27sLbNv3Zb6URY7TMjCeRgHSI1wt/o\n"
            "mEYL1RjHCqiv8HAWQ9ujXx5Ec3Ou4xo1G/m/FmyqTYonGI8dfMMuk1b4U3LLglbg\n"
            "gi/HP4+ThknFRd6f3CoAqCqbumhI5GpvfzE+fjyZlvgE4QFfRq/zxD3rEDmwMHy9\n"
            "QMPtFEvIfEJBQ+YRDSYE0uEClp+brvInyxMKSRxPhGdS5xRgnvlCMobz7riPTTW4\n"
            "cRPZdzLsbgvV5jjL+QCrbViyhiGwsczGMpiKzC6vblXNRyIIthqg5kOXdCZKAEN+\n"
            "zAgPfwIMGJbzkbie0ge5DaxUXq6UTZOgNzw=\n"
            "-----END CERTIFICATE-----\n";

        try {
            // Do the test here. If error throw expections
            CertificateX509 cert(badPem);
        } catch (const std::runtime_error& e) {
        } catch (const std::exception& e) {
            FAIL(e.what());
        }
    }
}
