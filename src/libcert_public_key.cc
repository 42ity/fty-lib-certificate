/*  =========================================================================
    libcert_public_key - Public Key

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
    libcert_public_key - Public Key
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
    PublicKey::PublicKey(EVP_PKEY * key)
    {
        if(key == NULL) throw std::runtime_error("Impossible to create the public key");
        m_evpPkey = key;
    }

    PublicKey::~PublicKey()
    {
        EVP_PKEY_free(m_evpPkey);
    }
        
    std::string PublicKey::getPem() const
    {
        BIO * bioOut = BIO_new(BIO_s_mem());
        std::string pem;
        
        PEM_write_bio_PUBKEY(bioOut, m_evpPkey);

        BUF_MEM *bioBuffer;
        BIO_get_mem_ptr(bioOut, &bioBuffer);
        pem = std::string(bioBuffer->data, bioBuffer->length);

        BIO_free(bioOut);

        return pem;
    }

} //namespace fty


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
libcert_public_key_test (bool verbose)
{
    printf (" * libcert_public_key: ");

    //  @selftest
    //  Simple create/destroy test

    //  @end
    printf ("OK\n");
}
