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

#ifndef LIBCERT_KEYS_H_INCLUDED
#define LIBCERT_KEYS_H_INCLUDED

#include <string>
#include <openssl/x509.h>

#include "libcert_pem_exportable.h"
#include "libcert_public_key.h"

namespace fty
{
    //note: A private key containe also the public key matching with it.
    class Keys : public PemExportable
    {
    public:
        Keys(const std::string & privateKeyPem);
        ~Keys();

        std::string getPem() const override;
        PublicKey getPublicKey() const;
    private:
        EVP_PKEY * m_evpPkey = NULL;
    };

} // namespace fty

//  Self test of this class
void libcert_keys_test (bool verbose);



#endif
