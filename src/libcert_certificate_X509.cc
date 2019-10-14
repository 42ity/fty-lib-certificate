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

    PublicKey CertificateX509::getPublicKey() const
    {
        return PublicKey(X509_get_pubkey(m_x509));
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

void
libcert_certificate_x509_test (bool verbose)
{
    printf (" * libcert_certificate_x509: ");

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
