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

#ifndef LIBCERT_PUBLIC_KEY_H_INCLUDED
#define LIBCERT_PUBLIC_KEY_H_INCLUDED

#include <string>
#include <openssl/evp.h>

#include "libcert_pem_exportable.h"

namespace fty
{
    class CertificateX509;
    class Csr509;
    class Keys;

    class PublicKey : public PemExportable
    {
    public:
        ~PublicKey();

        std::string getPem() const override;
    private:
        PublicKey(EVP_PKEY * key);
        EVP_PKEY * m_evpPkey = NULL;

    friend class CertificateX509;
    friend class CsrX509;
    friend class Keys;
    };
}

//  Self test of this class
void libcert_public_key_test (bool verbose);

#endif
