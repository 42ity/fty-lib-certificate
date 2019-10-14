/*  =========================================================================
    libcert_keys - Keys (Public and Private)

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
    libcert_keys - Keys (Public and Private)
@discuss
@end
*/

#include "fty_lib_certificate_classes.h"

#include <stdexcept>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

namespace fty
{
    Keys::Keys(const std::string & privateKeyPem)
    {      
        BIO * bio = BIO_new_mem_buf((void*)privateKeyPem.c_str(), privateKeyPem.length());

        if(bio == NULL)
        {
            throw std::runtime_error("Impossible to create the private key");
        }

        m_evpPkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if ( m_evpPkey == NULL)
        {
            throw std::runtime_error("Impossible to create the private key");
        }
    }

    Keys::~Keys()
    {
        EVP_PKEY_free(m_evpPkey);
    }
        
    std::string Keys::getPem() const
    {
        BIO * bioOut = BIO_new(BIO_s_mem());
        std::string pem;
        
        PEM_write_bio_PrivateKey(bioOut, m_evpPkey, NULL, NULL, 0, 0, NULL);

        BUF_MEM *bioBuffer;
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
libcert_keys_test (bool verbose)
{
    printf (" * libcert_keys: ");

    //  @selftest
    //  Simple create/destroy test

    //  @end
    printf ("OK\n");
}
