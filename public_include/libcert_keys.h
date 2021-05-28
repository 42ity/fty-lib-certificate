/*  =========================================================================
    libcert_keys - Keys class header

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
#include "libcert_pem_exportable.h"
#include "libcert_public_key.h"
#include <string>

typedef struct evp_pkey_st EVP_PKEY;

namespace fty {

// EC curve types
enum ECKeyType
{
    PRIME256V1
};

class CertificateX509;
class CsrX509;

// note: A private key containe also the public key matching with it.
class Keys : public PemExportable
{
public:
    Keys(const std::string& privateKeyPem);
    Keys(const Keys& key);
    ~Keys();

    std::string getPem() const override;
    PublicKey   getPublicKey() const;

    // class methods
    static Keys generateRSA(int bits);
    static Keys generateEC(ECKeyType keyType);

private:
    Keys(EVP_PKEY* evpPkey); // private copy ctor
    void importPem(const std::string& privateKeyPem);

    EVP_PKEY* m_evpPkey = nullptr;

    friend class CertificateX509;
    friend class CsrX509;
};

} // namespace fty
