/*  =========================================================================
    libcert_public_key - Public Key

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
    libcert_public_key - Public Key
@discuss
@end
*/

#include "fty_lib_certificate_classes.h"
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sstream>
#include <stdexcept>

namespace fty {
PublicKey::PublicKey(EVP_PKEY* key)
{
    if (key == NULL)
        throw std::runtime_error("Impossible to create the public key");
    m_evpPkey = key;
}

PublicKey::~PublicKey()
{
    EVP_PKEY_free(m_evpPkey);
}

std::string PublicKey::getPem() const
{
    BIO*        bioOut = BIO_new(BIO_s_mem());
    std::string pem;

    PEM_write_bio_PUBKEY(bioOut, m_evpPkey);

    BUF_MEM* bioBuffer;
    BIO_get_mem_ptr(bioOut, &bioBuffer);
    pem = std::string(bioBuffer->data, bioBuffer->length);

    BIO_free(bioOut);

    return pem;
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

void libcert_public_key_test(bool /* verbose */)
{
    printf(" * libcert_public_key: ");

    //  @selftest
    //  Simple create/destroy test

    //  @end
    printf("OK\n");
}
