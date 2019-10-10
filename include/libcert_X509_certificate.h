/*  =========================================================================
    libcert_x509_certificate - X509 certificate

    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of CZMQ, the high-level C binding for 0MQ:
    http://czmq.zeromq.org.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

#ifndef LIBCERT_X509_CERTIFICATE_H_INCLUDED
#define LIBCERT_X509_CERTIFICATE_H_INCLUDED

#include <string>
#include <openssl/x509.h>

namespace fty
{
    class CertificateX509
    {   
    public:
        explicit CertificateX509(const std::string & certPem);
        CertificateX509(const CertificateX509 & x509);
        ~CertificateX509();
        
        std::string getSubject() const;
        std::string getDetails() const;
        std::string getPem() const;
        
    private:
        X509 * m_x509 = NULL;

        void importPem(const std::string & certPem);
    };

    inline bool operator==(const CertificateX509& lhs, const CertificateX509& rhs){ return (lhs.getPem() == rhs.getPem()); }
    inline bool operator!=(const CertificateX509& lhs, const CertificateX509& rhs){ return !(lhs == rhs); }
} // namespace fty

//  Self test of this class
void libcert_x509_certificate_test (bool verbose);



#endif
