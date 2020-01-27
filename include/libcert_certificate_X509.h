/*  =========================================================================
    libcert_certificate_X509 - X509 Certificate class

    Copyright (C) 2014 - 2020 Eaton

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

#ifndef LIBCERT_CERTIFICATE_X509_H_INCLUDED
#define LIBCERT_CERTIFICATE_X509_H_INCLUDED

#include <string>
#include <memory>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "libcert_pem_exportable.h"
#include "libcert_public_key.h"

#include "libcert_certificate_config.h"

namespace fty
{
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

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

        // class methods
        static CertificateX509 selfSignSha256(const Keys &key, const CertificateConfig &cfg);
        
    private:
        CertificateX509(X509Ptr cert);
        void importPem(const std::string & certPem);

        X509 * m_x509 = NULL;
    };

} // namespace fty

//  Self test of this class
void libcert_certificate_x509_test (bool verbose);

#endif
