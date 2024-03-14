/*  =========================================================================
    libcert_keys - Keys (Public and Private)

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
    libcert_keys - Keys (Public and Private)
@discuss
@end
*/

#include "libcert_keys.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace fty {
Keys::Keys(const std::string& privateKeyPem)
{
    importPem(privateKeyPem);
}

Keys::Keys(const Keys& key)
{
    importPem(key.getPem());
}

Keys::~Keys()
{
    EVP_PKEY_free(m_evpPkey);
}

std::string Keys::getPem() const
{
    BIO*        bioOut = BIO_new(BIO_s_mem());
    std::string pem;

    PEM_write_bio_PrivateKey(bioOut, m_evpPkey, NULL, NULL, 0, 0, NULL);

    BUF_MEM* bioBuffer{nullptr};
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

Keys Keys::generateRSA(int bits)
{
    EVP_PKEY* evpPkey = EVP_RSA_gen(bits);
    if (evpPkey == NULL) {
        throw std::runtime_error("Unable to create RSA key: RSA generation failed");
    }

    return Keys(evpPkey);
}

Keys Keys::generateEC(ECKeyType keyType)
{
    char* keyName{nullptr};
    if (keyType == PRIME256V1) {
        // asn1 flag is automatically set for "prime256v1" EC
        keyName = SN_X9_62_prime256v1;
    }
    else {
        throw std::runtime_error("Unable to create EC key: keyType not handled");
    }

    EVP_PKEY* evpPkey = EVP_EC_gen(keyName);
    if (evpPkey == NULL) {
        throw std::runtime_error("Unable to create EC key: EC generation failed");
    }

    return Keys(evpPkey);
}

// private constructor
Keys::Keys(EVP_PKEY* evpPkey)
{
    m_evpPkey = evpPkey;

    if (m_evpPkey == NULL) {
        throw std::runtime_error("Impossible to create the private key");
    }
}

void Keys::importPem(const std::string& privateKeyPem)
{
    BIO* bio =
        BIO_new_mem_buf(static_cast<const void*>(privateKeyPem.c_str()), static_cast<int>(privateKeyPem.length()));

    if (bio == NULL) {
        throw std::runtime_error("Impossible to create the private key");
    }

    m_evpPkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (m_evpPkey == NULL) {
        throw std::runtime_error("Impossible to create the private key");
    }
}

} // namespace fty
