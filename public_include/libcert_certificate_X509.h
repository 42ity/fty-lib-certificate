/*  =========================================================================
    libcert_certificate_X509 - X509 Certificate class

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

#pragma once

#include "libcert_certificate_config.h"
#include "libcert_pem_exportable.h"
#include "libcert_public_key.h"
#include <memory>
#include <string>

typedef struct x509_st X509;

namespace fty {
using X509Ptr = std::unique_ptr<X509, void(*)(X509*)>;

class CertificateX509 : public PemExportable
{
public:
    explicit CertificateX509(const std::string& certPem);
    CertificateX509(const CertificateX509& x509);
    ~CertificateX509();

    std::string getSubject() const;
    std::string getDetails() const;
    std::string getPem() const override;

    PublicKey getPublicKey() const;

    // class methods
    static CertificateX509 selfSignSha256(const Keys& key, const CertificateConfig& cfg);

private:
    CertificateX509(X509Ptr cert);
    void importPem(const std::string& certPem);

    X509* m_x509 = nullptr;
};

} // namespace fty
