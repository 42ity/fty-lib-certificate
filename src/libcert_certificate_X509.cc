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
#include <openssl/ssl.h>
#include <openssl/pem.h>

namespace fty
{
    //This link is the best source code to extract everything for human: http://www.zedwood.com/article/c-openssl-parse-x509-certificate-pem 

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

    // std::string CertificateX509::getSubject() const
    // {
    //     char * str = X509_NAME_oneline(X509_get_subject_name(m_x509), NULL, 0);

    //     std::string returnValue(str);

    //     free(str);

    //     return returnValue;
    // }

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

    // class methods

    #define SERIAL_RAND_BITS 64

    CertificateX509 CertificateX509::selfSignSha256(const Keys &key, const CertificateConfig &cfg)
    {
        // generate new X509 certificate
        X509 * cert = X509_new();

        if (cert == NULL)
        {
            throw std::runtime_error ("Impossible to create certificate");
        }

        // set version (version number - 1)
        if ((X509_set_version(cert, cfg.getVersion() - 1)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set certificate version");
        }

        // generate serial number
        {
            ASN1_INTEGER *serialNumber = ASN1_INTEGER_new();
            if (serialNumber == NULL)
            {
                throw std::runtime_error ("Unable to set certificate version");
            }

            BIGNUM *bn = BN_new();
            if (bn == NULL)
            {
                X509_free(cert);
                ASN1_INTEGER_free(serialNumber);
                throw std::runtime_error ("Unable to set certificate version");
            }

            if ((BN_pseudo_rand(bn, SERIAL_RAND_BITS, 0, 0)) != 1)
            {
                X509_free(cert);
                ASN1_INTEGER_free(serialNumber);
                BN_free(bn);
                throw std::runtime_error ("Unable to generate big pseudo random number");
            }
            
            if((serialNumber = BN_to_ASN1_INTEGER(bn, serialNumber)) == NULL)
            {
                X509_free(cert);
                ASN1_INTEGER_free(serialNumber);
                BN_free(bn);
                throw std::runtime_error ("Unable to convert bn to ASN1 integer");
            }
            
            if ((X509_set_serialNumber(cert, serialNumber)) != 1)
            {
                X509_free(cert);
                ASN1_INTEGER_free(serialNumber);
                BN_free(bn);
                throw std::runtime_error ("Unable to set serial number");
            }

            ASN1_INTEGER_free(serialNumber);
            BN_free(bn);
        }

        // setting start and expiration time
        std::chrono::time_point<std::chrono::system_clock> currentTime = std::chrono::system_clock::now();
        int64_t epochSeconds = std::chrono::time_point_cast<std::chrono::seconds>(currentTime).time_since_epoch().count();

        if((X509_gmtime_adj(X509_get_notBefore(cert), cfg.getValidFrom() - epochSeconds)) == NULL)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set valid from field");
        }
        if((X509_gmtime_adj(X509_get_notAfter(cert), cfg.getValidTo() - epochSeconds)) == NULL)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set valid to field");
        }

        // set public key
        if((X509_set_pubkey(cert, key.m_evpPkey)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set public key");
        }

        // get subject reference
        X509_NAME *certName = X509_get_subject_name(cert);

        // set country "C"
        if((X509_NAME_add_entry_by_txt(certName, "C", MBSTRING_ASC, (unsigned char *) cfg.getCountry().c_str(), -1, -1, 0)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set country");
        }
        // set state "ST"
        if((X509_NAME_add_entry_by_txt(certName, "ST", MBSTRING_ASC, (unsigned char *) cfg.getState().c_str(), -1, -1, 0)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set state");
        }
        // set locality "L"
        if((X509_NAME_add_entry_by_txt(certName, "L", MBSTRING_ASC, (unsigned char *) cfg.getLocality().c_str(), -1, -1, 0)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set locality");
        }
        // set organization name "O"
        if((X509_NAME_add_entry_by_txt(certName, "O", MBSTRING_ASC, (unsigned char *) cfg.getOrganization().c_str(), -1, -1, 0)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set organization");
        }
        // set organization unit "OU"
        if((X509_NAME_add_entry_by_txt(certName, "OU", MBSTRING_ASC, (unsigned char *) cfg.getOrganizationUnit().c_str(), -1, -1, 0)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set organization unit");
        }
        // set common name "CN"
        if((X509_NAME_add_entry_by_txt(certName, "CN", MBSTRING_ASC, (unsigned char *) cfg.getCommonName().c_str(), -1, -1, 0)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set common name");
        }
        // set email "email"
        if((X509_NAME_add_entry_by_txt(certName, "OU", MBSTRING_ASC, (unsigned char *) cfg.getEmail().c_str(), -1, -1, 0)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set email");
        }
        // set issuer
        if((X509_set_issuer_name(cert, certName)) == 0)
        {
            X509_free(cert);
            throw std::runtime_error ("Unable to set issuer");
        }
       
        // set ip address
        for (const std::string & ip : cfg.getIpList())
        {
            X509_EXTENSION *ex;
	        X509V3_CTX ctx;

            // set context
            X509V3_set_ctx_nodb(&ctx);

            X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

            std::string ipAltNameEntry("IP:" + ip);

            ex = X509V3_EXT_conf_nid( NULL, &ctx, NID_subject_alt_name, const_cast<char*>(ipAltNameEntry.c_str()));
            if (!ex)
            {
                X509_EXTENSION_free(ex);
                X509_free(cert);
                throw std::runtime_error ("Unable to set IP");
            }

            X509_add_ext(cert, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // set dns address
        for (const std::string & dns : cfg.getDnsList())
        {
            X509_EXTENSION *ex;
	        X509V3_CTX ctx;

            // set context
            X509V3_set_ctx_nodb(&ctx);

            X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

            std::string dnsAltNameEntry("DNS:" + dns);
	        
            ex = X509V3_EXT_conf_nid( NULL, &ctx, NID_subject_alt_name, const_cast<char*>(dnsAltNameEntry.c_str()));
            if (!ex)
            {
                X509_EXTENSION_free(ex);
                X509_free(cert);
                throw std::runtime_error ("Unable to set DNS");
            }

            X509_add_ext(cert, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // Finally perform the signing process
        if ( !X509_sign( cert, key.m_evpPkey, EVP_sha256() ) )
        {
            throw std::runtime_error( "Failed signing of the x509 certificate." );
        }

        return CertificateX509(cert);
    }

    // private constructor
    CertificateX509::CertificateX509(X509 * cert)
    {
        m_x509 = cert;

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

#include <iostream>

void
libcert_certificate_x509_test (bool verbose)
{
    using namespace fty;

    printf (" * libcert_certificate_x509: ");

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

    std::cout << certificate.getDetails() << std::endl;

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
