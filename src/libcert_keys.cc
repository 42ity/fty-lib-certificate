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

    BUF_MEM* bioBuffer;
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
    // 1. generate rsa key
    BIGNUM* bne = BN_new();

    if ((BN_set_word(bne, RSA_F4)) != 1) {
        BN_free(bne);
        throw std::runtime_error("Unable to create private key: big number generation failed");
    }

    RSA* rsaKey = RSA_new();

    if ((RSA_generate_key_ex(rsaKey, bits, bne, NULL)) != 1) {
        BN_free(bne);
        RSA_free(rsaKey);
        throw std::runtime_error("Unable to create private key: RSA generation failed");
    }

    BN_free(bne);

    EVP_PKEY* evpPkey = EVP_PKEY_new();

    if ((EVP_PKEY_assign_RSA(evpPkey, rsaKey) == 0)) {
        RSA_free(rsaKey);
        EVP_PKEY_free(evpPkey);
        throw std::runtime_error("Failed to assign RSA key to private key.");
    }

    return Keys(evpPkey);
}

Keys Keys::generateEC(ECKeyType keyType)
{
    auto realKey = [&]() {
        switch (keyType) {
        case PRIME256V1:
            return NID_X9_62_prime256v1;
        default:
            break;
        }
        return 0;
    };

    EC_KEY* ecKey = EC_KEY_new_by_curve_name(realKey());
    EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

    if (EC_KEY_generate_key(ecKey) == 0) {
        EC_KEY_free(ecKey);
        throw std::runtime_error("Unable to create private key: EC keygen failed");
    }

    EVP_PKEY* evpPkey = EVP_PKEY_new();

    if (EVP_PKEY_assign_EC_KEY(evpPkey, ecKey) == 0) {
        EC_KEY_free(ecKey);
        EVP_PKEY_free(evpPkey);
        throw std::runtime_error("Failed to assign EC key to private key.");
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
