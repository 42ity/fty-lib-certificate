/*  =========================================================================
    libcert_certificate_x509 - X509 certificate

    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of CZMQ, the high-level C binding for 0MQ:
    http://czmq.zeromq.org.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

/*
@header
    libcert_certificate_x509 - X509 certificate
@discuss
@end
*/

#include "fty_lib_certificate_classes.h"

#include <stdexcept>
#include <sstream>
#include <list>
#include <chrono>

#include <openssl/ssl.h>
#include <openssl/pem.h>

namespace fty
{
    //This link is the best source code to extract everything for human: http://www.zedwood.com/article/c-openssl-parse-x509-certificate-pem 
    using SerialNumberPtr = std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
    using BigNumberPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

    /* Local helper function definitions */
    static SerialNumberPtr generateSerialNumber();
    static void addCertificateExt(X509Ptr & cert, std::string type, std::string value);
    static void X509AddEntry(X509Ptr & cert, const std::string & fieldName, const std::string & fieldData);
    
    /* Local constants */
    static const std::string EXT_URI_TYPE = "URI:";
    static const std::string EXT_IP_TYPE = "IP:";
    static const std::string EXT_DNS_TYPE = "DNS:";
    static const std::string EXT_EMAIL_TYPE = "email:";
    static const std::string EXT_DIR_NAME = "dirName:";
    static const std::string EXT_RID_NAME = "RID:";
    static const std::string EXT_UTF8_NAME = "UTF8:";
    static const std::string EXT_OTHER_TYPE = "OtherName:";

    static const int SERIAL_RAND_BITS = 64;

    CertificateX509::CertificateX509(const std::string & certPem)
    {
        importPem(certPem);
    }

    CertificateX509::CertificateX509(const CertificateX509 & x509)
    {
        importPem(x509.getPem());
    }

    CertificateX509::~CertificateX509()
    {
        // Cleanup
	    X509_free(m_x509);
    }

    std::string CertificateX509::getSubject() const
    {
        char * str = X509_NAME_oneline(X509_get_subject_name(m_x509), NULL, 0);

        std::string returnValue(str);

        free(str);

        return returnValue;
    }

    std::string CertificateX509::getDetails() const
    {
        BIO * bioOut = BIO_new(BIO_s_mem());
        std::string details;

        X509_print(bioOut, m_x509);

        BUF_MEM *bioBuffer;
        BIO_get_mem_ptr(bioOut, &bioBuffer);
        details = std::string(bioBuffer->data, bioBuffer->length);

        BIO_free(bioOut);

        return details;
    }

    std::string CertificateX509::getPem() const
    {
        BIO * bioOut = BIO_new(BIO_s_mem());
        std::string pem;
        
        PEM_write_bio_X509(bioOut, m_x509);

        BUF_MEM *bioBuffer;
        BIO_get_mem_ptr(bioOut, &bioBuffer);
        pem = std::string(bioBuffer->data, bioBuffer->length);

        BIO_free(bioOut);

        return pem;
    }

    PublicKey CertificateX509::getPublicKey() const
    {
        return PublicKey(X509_get_pubkey(m_x509));
    }

    CertificateX509 CertificateX509::selfSignSha256(const Keys &key, const CertificateConfig &cfg)
    {
        // generate new X509 certificate
        X509Ptr cert(X509_new(), &X509_free);

        if (cert.get() == NULL)
        {
            throw std::runtime_error ("Impossible to create certificate");
        }

        // set version (version number - 1)
        if ((X509_set_version(cert.get(), cfg.getVersion() - 1)) == 0)
        {
            throw std::runtime_error ("Unable to set certificate version");
        }

        // generate serial number
        SerialNumberPtr serialNumber = generateSerialNumber();
    
        if ((X509_set_serialNumber(cert.get(), serialNumber.get())) != 1)
        {
            throw std::runtime_error ("Unable to set serial number");
        }

        // setting start and expiration time (getting current time to set offset)
        std::chrono::time_point<std::chrono::system_clock> currentTime = std::chrono::system_clock::now();
        int64_t epochSeconds = std::chrono::time_point_cast<std::chrono::seconds>(currentTime).time_since_epoch().count();

        if((X509_gmtime_adj(X509_get_notBefore(cert.get()), cfg.getValidFrom() - epochSeconds)) == NULL)
        {
            throw std::runtime_error ("Unable to set valid from field");
        }

        if((X509_gmtime_adj(X509_get_notAfter(cert.get()), cfg.getValidTo() - epochSeconds)) == NULL)
        {
            throw std::runtime_error ("Unable to set valid to field");
        }

        // set public key
        if((X509_set_pubkey(cert.get(), key.m_evpPkey)) == 0)
        {
            throw std::runtime_error ("Unable to set public key");
        }

        X509AddEntry(cert, "C", cfg.getCountry());
        X509AddEntry(cert, "ST", cfg.getState());
        X509AddEntry(cert, "L",  cfg.getLocality());
        X509AddEntry(cert, "O",  cfg.getOrganization());
        X509AddEntry(cert, "OU", cfg.getOrganizationUnit());
        X509AddEntry(cert, "CN", cfg.getCommonName());
        X509AddEntry(cert, "OU", cfg.getEmail());

        // set issuer
        if((X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()))) == 0)
        {
            throw std::runtime_error ("Unable to set issuer");
        }
       
        // set ip addresses
        for (const std::string & ip : cfg.getIpList())
        {
            addCertificateExt(cert, EXT_IP_TYPE, ip);
        }

        // set dns addresses
        for (const std::string & dns : cfg.getDnsList())
        {
            addCertificateExt(cert, EXT_DNS_TYPE, dns);
        }

        // signing certificate
        if ( !X509_sign(cert.get(), key.m_evpPkey, EVP_sha256()))
        {
            throw std::runtime_error( "Unable to sign x509 certificate" );
        }

        return CertificateX509(std::move(cert));
    }

    CertificateX509::CertificateX509(X509Ptr cert)
    {
        m_x509 = cert.release();

        if (m_x509 == NULL)
        {
            throw std::runtime_error ("Impossible to create certificate");
        }
    }

    void CertificateX509::importPem(const std::string & certPem)
    {
        X509_free(m_x509);

        BIO * bio = BIO_new_mem_buf((void*)certPem.c_str(), certPem.length());

        if(bio == NULL)
        {
            throw std::runtime_error("Impossible to read the certificate PEM");
        }

        m_x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if ( m_x509 == NULL)
        {
            throw std::runtime_error("Impossible to read the certificate PEM");
        }
    }

    /* Local helper function */    

    SerialNumberPtr generateSerialNumber()
    {
        const int SERIAL_RAND_BITS = 64;
        
        //create a bignumber for serial number generation
        BigNumberPtr bn(BN_new(), &BN_free);

        if (bn.get() == NULL)
        {
            throw std::runtime_error ("Unable to allocate big pseudo random number");
        }

        if ((BN_pseudo_rand(bn.get(), SERIAL_RAND_BITS, 0, 0)) != 1)
        {
            throw std::runtime_error ("Unable to generate big pseudo random number");
        }

        SerialNumberPtr serialNumber (BN_to_ASN1_INTEGER(bn.get(), NULL), &ASN1_INTEGER_free);
        
        if(serialNumber.get() == NULL)
        {
            throw std::runtime_error("Unable to convert bn to ASN1 integer");
        }  

        return std::move(serialNumber);
    }

    void addCertificateExt(X509Ptr & cert, std::string type, std::string value){
        X509_EXTENSION *ex;
        X509V3_CTX ctx;

        // set context
        X509V3_set_ctx_nodb(&ctx);

        X509V3_set_ctx(&ctx, cert.get(), cert.get(), NULL, NULL, 0);

        std::string ipAltNameEntry(type + value);

        ex = X509V3_EXT_conf_nid( NULL, &ctx, NID_subject_alt_name, const_cast<char*>(ipAltNameEntry.c_str()));
        if (!ex)
        {
            X509_EXTENSION_free(ex);
            throw std::runtime_error ("Unable to set IP");
        }

        X509_add_ext(cert.get(), ex, -1);
        X509_EXTENSION_free(ex);
    }

    void X509AddEntry(X509Ptr & cert, const std::string & fieldName, const std::string & fieldData)
    {
        X509_NAME *certName = X509_get_subject_name(cert.get());

        if((X509_NAME_add_entry_by_txt(certName, fieldName.c_str(), MBSTRING_ASC, (unsigned char *) fieldData.c_str(), -1, -1, 0)) == 0)
        {
            throw std::runtime_error ("Unable to "+fieldName+" to the value "+fieldData);
        }
    }
} // namepsace fty

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
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#include <iostream>
#include <vector>

void
libcert_certificate_x509_test (bool verbose)
{
    using namespace fty;

    std::vector<std::pair<std::string, bool>> testsResults;

    printf (" * libcert_certificate_x509: ");

    std::string testNumber;
    std::string testName;

    //Next test
    testNumber = "1.1";
    testName = "Sign certificate-> success case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections

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
            config.setIpList({"192.168.0.1","10.22.45.52"});
            config.setDnsList({"myTest.eaton.com"});

            CertificateX509 certificate = CertificateX509::selfSignSha256(keys, config);

            // std::cout << certificate.getDetails() << std::endl;

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch (const std::exception &e) {
            printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
            printf ("Error: %s\n", e.what ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
        }
    }
    printf ("OK\n");

    //Next test
    testNumber = "1.2";
    testName = "Sign certificate-> bad case (empty configuration)";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections

            Keys keys = Keys::generateRSA(2048);

            CertificateConfig config;

            CertificateX509 certificate = CertificateX509::selfSignSha256(keys, config);

            // std::cout << certificate.getDetails() << std::endl;

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch(const std::runtime_error& e)
        {
            //expected error
            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
        }
        catch(const std::exception& e)
        {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n",e.what());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,false);
        }
    }
    printf ("OK\n");

    //Next test
    testNumber = "2.1";
    testName = "Check exported key is equal to the one used to sign-> success case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());

        try {
            //Do the test here. If error throw expections

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
            config.setIpList({"192.168.0.1","10.22.45.52"});
            config.setDnsList({"myTest.eaton.com"});

            CertificateX509 certificate = CertificateX509::selfSignSha256(keys, config);

            if (keys.getPublicKey() != certificate.getPublicKey())
            {
                throw std::runtime_error("PEM keys mismatch");
            }

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch (const std::exception &e) {
            printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
            printf ("Error: %s\n", e.what ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
        }
    }
    printf ("OK\n");

    //Next test
    testNumber = "3.1";
    testName = "Check certificate import-> success case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());
        
        std::string goodPem =
        "-----BEGIN CERTIFICATE-----\n"\
        "MIID1jCCAr6gAwIBAgIJALMAxv/ljVRoMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD\n"\
        "VQQGEwJDWjEOMAwGA1UECAwFUHJhaGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQK\n"\
        "DAVFYXRvbjEMMAoGA1UECwwDRFBRMRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRl\n"\
        "MSAwHgYDVQQLDBdNYXVyb0d1ZXJyZXJhQGVhdG9uLmNvbTAeFw0xOTEwMjMxNDIx\n"\
        "MDlaFw0yMDEwMjMxNDIxMDlaMIGIMQswCQYDVQQGEwJDWjEOMAwGA1UECAwFUHJh\n"\
        "aGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQKDAVFYXRvbjEMMAoGA1UECwwDRFBR\n"\
        "MRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRlMSAwHgYDVQQLDBdNYXVyb0d1ZXJy\n"\
        "ZXJhQGVhdG9uLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7T\n"\
        "GSq1qrr16SP4RfDePWds6SZMRr+ovTis+Iub88tst+hQOZRrCby81cyfYh39dqpY\n"\
        "mU1K1a1+fppD7Ci2unZAvjoKQEQzRA+1ie7Yo5fRdiXw7DSFDzQ9VypGCvQaWe20\n"\
        "kLpv8io34oJKen1Qa5+oMfthivQCXZ1jW3ulRW7MzgtmZyO1hZyS20L5uvDytnG1\n"\
        "B0q+8l32YaLJW1W/Swy336+5sMzLbdomMPgLnz3QLBGDENwHH6Fj5OGmejG94KSP\n"\
        "7mjambagdKZjYZxrsKE6CzY2RjVfCGgf6IqczCN5pxl6F4TPzjD/HqZ4gGSajVEB\n"\
        "NlEj6ZvOuLk2x0553csCAwEAAaNBMD8wDwYDVR0RBAgwBocEwKgAATAPBgNVHREE\n"\
        "CDAGhwQKFi00MBsGA1UdEQQUMBKCEG15VGVzdC5lYXRvbi5jb20wDQYJKoZIhvcN\n"\
        "AQELBQADggEBAFs5cQEaNDHdfBIeDMrfHN27sLbNv3Zb6URY7TMjCeRgHSI1wt/o\n"\
        "mEYL1RjHCqiv8HAWQ9ujXx5Ec3Ou4xo1G/m/FmyqTYonGI8dfMMuk1b4U3LLglbg\n"\
        "gi/HP4+ThknFRd6f3CoAqCqbumhI5GpvfzE+fjyZlvgE4QFfRq/zxD3rEDmwMHy9\n"\
        "QMPtFEvIfEJBQ+YRDSYE0uEClp+brvInyxMKSRxPhGdS5xRgnvlCMobz7riPTTW4\n"\
        "cRPZdzLsbgvV5jjL+QCrbViyhiGwsczGMpiKzC6vblXNRyIIthqg5kOXdCZKAEN+\n"\
        "zAgPfwIMGJbzkbie0ge5DaxUXq6UTZOgNzw=\n"\
        "-----END CERTIFICATE-----\n";

        try {
            //Do the test here. If error throw expections

            CertificateX509 cert(goodPem);

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch (const std::exception &e) {
            printf (" *<=  Test #%s > Failed\n", testNumber.c_str ());
            printf ("Error: %s\n", e.what ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, false);
        }
    }
    printf ("OK\n");

    //Next test
    testNumber = "3.2";
    testName = "Check certificate import-> bad case";
    printf ("\n----------------------------------------------------------------"
            "-------\n");
    {
        printf (" *=>  Test #%s %s\n", testNumber.c_str (), testName.c_str ());
        
        std::string badPem =
        "-----BEGIN-----\n"\
        "MIID1jCCAr6gAwIBAgIJALMAxv/ljVRoMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD\n"\
        "VQQGEwJDWjEOMAwGA1UECAwFUHJhaGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQK\n"\
        "DAVFYXRvbjEMMAoGA1UECwwDRFBRMRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRl\n"\
        "MSAwHgYDVQQLDBdNYXVyb0d1ZXJyZXJhQGVhdG9uLmNvbTAeFw0xOTEwMjMxNDIx\n"\
        "MDlaFw0yMDEwMjMxNDIxMDlaMIGIMQswCQYDVQQGEwJDWjEOMAwGA1UECAwFUHJh\n"\
        "aGExDjAMBgNVBAcMBVByYWhhMQ4wDAYDVQQKDAVFYXRvbjEMMAoGA1UECwwDRFBR\n"\
        "MRkwFwYDVQQDDBB0ZXN0LWNlcnRpZmljYXRlMSAwHgYDVQQLDBdNYXVyb0d1ZXJy\n"\
        "ZXJhQGVhdG9uLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL7T\n"\
        "GSq1qrr16SP4RfDePWds6SZMRr+ovTis+Iub88tst+hQOZRrCby81cyfYh39dqpY\n"\
        "mU1K1a1+fppD7Ci2unZAvjoKQEQzRA+1ie7Yo5fRdiXw7DSFDzQ9VypGCvQaWe20\n"\
        "kLpv8io34oJKen1Qa5+oMfthivQCXZ1jW3ulRW7MzgtmZyO1hZyS20L5uvDytnG1\n"\
        "B0q+8l32YaLJW1W/Swy336+5sMzLbdomMPgLnz3QLBGDENwHH6Fj5OGmejG94KSP\n"\
        "7mjambagdKZjYZxrsKE6CzY2RjVfCGgf6IqczCN5pxl6F4TPzjD/HqZ4gGSajVEB\n"\
        "NlEj6ZvOuLk2x0553csCAwEAAaNBMD8wDwYDVR0RBAgwBocEwKgAATAPBgNVHREE\n"\
        "CDAGhwQKFi00MBsGA1UdEQQUMBKCEG15VGVzdC5lYXRvbi5jb20wDQYJKoZIhvcN\n"\
        "AQELBQADggEBAFs5cQEaNDHdfBIeDMrfHN27sLbNv3Zb6URY7TMjCeRgHSI1wt/o\n"\
        "mEYL1RjHCqiv8HAWQ9ujXx5Ec3Ou4xo1G/m/FmyqTYonGI8dfMMuk1b4U3LLglbg\n"\
        "gi/HP4+ThknFRd6f3CoAqCqbumhI5GpvfzE+fjyZlvgE4QFfRq/zxD3rEDmwMHy9\n"\
        "QMPtFEvIfEJBQ+YRDSYE0uEClp+brvInyxMKSRxPhGdS5xRgnvlCMobz7riPTTW4\n"\
        "cRPZdzLsbgvV5jjL+QCrbViyhiGwsczGMpiKzC6vblXNRyIIthqg5kOXdCZKAEN+\n"\
        "zAgPfwIMGJbzkbie0ge5DaxUXq6UTZOgNzw=\n"\
        "-----END CERTIFICATE-----\n";

        try {
            //Do the test here. If error throw expections

            CertificateX509 cert(badPem);

            printf (" *<=  Test #%s > OK\n", testNumber.c_str ());
            testsResults.emplace_back (" Test #" + testNumber + " " + testName, true);
        }
        catch(const std::runtime_error& e)
        {
            //expected error
            printf(" *<=  Test #%s > OK\n", testNumber.c_str());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,true);
        }
        catch(const std::exception& e)
        {
            printf(" *<=  Test #%s > Failed\n", testNumber.c_str());
            printf("Error: %s\n",e.what());
            testsResults.emplace_back (" Test #"+testNumber+" "+testName,false);
        }
    }
    printf ("OK\n");


    // collect results

    printf("\n-----------------------------------------------------------------------\n");

	uint32_t testsPassed = 0;
	uint32_t testsFailed = 0;


	printf("\tSummary tests from libcert_keys\n");
	for(const auto & result : testsResults)
	{
		if(result.second)
		{
			printf(ANSI_COLOR_GREEN"\tOK " ANSI_COLOR_RESET "\t%s\n",result.first.c_str());
			testsPassed++;
		}
		else
		{
			printf(ANSI_COLOR_RED"\tNOK" ANSI_COLOR_RESET "\t%s\n",result.first.c_str());
			testsFailed++;
		}
	}

	printf("\n-----------------------------------------------------------------------\n");

	if(testsFailed == 0)
	{
		printf(ANSI_COLOR_GREEN"\n %i tests passed, everything is ok\n" ANSI_COLOR_RESET "\n",testsPassed);
	}
	else
	{
		printf(ANSI_COLOR_RED"\n!!!!!!!! %i/%i tests did not pass !!!!!!!! \n" ANSI_COLOR_RESET "\n",testsFailed,(testsPassed+testsFailed));

		assert(false);
	}

    printf ("OK\n");
}
