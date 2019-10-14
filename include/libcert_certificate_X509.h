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

#ifndef LIBCERT_CERTIFICATE_X509_H_INCLUDED
#define LIBCERT_CERTIFICATE_X509_H_INCLUDED

#include <string>
#include <openssl/x509.h>

#include "libcert_pem_exportable.h"
#include "libcert_public_key.h"

namespace fty
{
    class CertificateX509 : public PemExportable
    {   
    public:
        explicit CertificateX509(const std::string & certPem);
        CertificateX509(const CertificateX509 & x509);
        ~CertificateX509();
        std::string getSubject() const;
        std::string getDetails() const;
        std::string getPem() const override;

        PublicKey getPublicKey() const;
        
    private:
        X509 * m_x509 = NULL;

        void importPem(const std::string & certPem);
    };

} // namespace fty

//  Self test of this class
void libcert_certificate_x509_test (bool verbose);

#endif
