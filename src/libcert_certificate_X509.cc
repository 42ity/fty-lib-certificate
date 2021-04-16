/*  =========================================================================
    libcert_certificate_x509 - X509 certificate

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
    libcert_certificate_x509 - X509 certificate
@discuss
@end
*/

#include "libcert_certificate_X509.h"
#include "libcert_keys.h"
#include <chrono>
#include <list>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sstream>
#include <stdexcept>

namespace fty {
// This link is the best source code to extract everything for human:
// http://www.zedwood.com/article/c-openssl-parse-x509-certificate-pem
using SerialNumberPtr = std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)>;
using BigNumberPtr    = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

/* Local helper function definitions */
static SerialNumberPtr generateSerialNumber();
static void            addExtension(X509Ptr& cert, int nid, const std::string& value);
static void            X509AddEntry(X509Ptr& cert, const std::string& fieldName, const std::string& fieldData);

/* Local constants */
static const std::string EXT_URI_TYPE   = "URI:";
static const std::string EXT_IP_TYPE    = "IP:";
static const std::string EXT_DNS_TYPE   = "DNS:";
static const std::string EXT_EMAIL_TYPE = "email:";
static const std::string EXT_DIR_NAME   = "dirName:";
static const std::string EXT_RID_NAME   = "RID:";
static const std::string EXT_UTF8_NAME  = "UTF8:";
static const std::string EXT_OTHER_TYPE = "OtherName:";

static const int SERIAL_RAND_BITS = 64;

CertificateX509::CertificateX509(const std::string& certPem)
{
    importPem(certPem);
}

CertificateX509::CertificateX509(const CertificateX509& x509)
{
    importPem(x509.getPem());
}

CertificateX509::~CertificateX509()
{
    // Cleanup
    X509_free(m_x509);
}

std::string CertificateX509::getSubject() const
{
    char* str = X509_NAME_oneline(X509_get_subject_name(m_x509), NULL, 0);

    std::string returnValue(str);

    free(str);

    return returnValue;
}

std::string CertificateX509::getDetails() const
{
    BIO*        bioOut = BIO_new(BIO_s_mem());
    std::string details;

    X509_print(bioOut, m_x509);

    BUF_MEM* bioBuffer;
    BIO_get_mem_ptr(bioOut, &bioBuffer);
    details = std::string(bioBuffer->data, bioBuffer->length);

    BIO_free(bioOut);

    return details;
}

std::string CertificateX509::getPem() const
{
    BIO*        bioOut = BIO_new(BIO_s_mem());
    std::string pem;

    PEM_write_bio_X509(bioOut, m_x509);

    BUF_MEM* bioBuffer;
    BIO_get_mem_ptr(bioOut, &bioBuffer);
    pem = std::string(bioBuffer->data, bioBuffer->length);

    BIO_free(bioOut);

    return pem;
}

PublicKey CertificateX509::getPublicKey() const
{
    return PublicKey(X509_get_pubkey(m_x509));
}

CertificateX509 CertificateX509::selfSignSha256(const Keys& key, const CertificateConfig& cfg)
{
    // generate new X509 certificate
    X509Ptr cert(X509_new(), &X509_free);

    if (cert.get() == NULL) {
        throw std::runtime_error("Impossible to create certificate");
    }

    // set version (version number - 1)
    if ((X509_set_version(cert.get(), cfg.getVersion() - 1)) == 0) {
        throw std::runtime_error("Unable to set certificate version");
    }

    // generate serial number
    SerialNumberPtr serialNumber = generateSerialNumber();

    if ((X509_set_serialNumber(cert.get(), serialNumber.get())) != 1) {
        throw std::runtime_error("Unable to set serial number");
    }

    // setting start and expiration time (getting current time to set offset)
    std::chrono::time_point<std::chrono::system_clock> currentTime = std::chrono::system_clock::now();
    int64_t epochSeconds = std::chrono::time_point_cast<std::chrono::seconds>(currentTime).time_since_epoch().count();

    if ((X509_gmtime_adj(X509_get_notBefore(cert.get()), cfg.getValidFrom() - epochSeconds)) == NULL) {
        throw std::runtime_error("Unable to set valid from field");
    }

    if ((X509_gmtime_adj(X509_get_notAfter(cert.get()), cfg.getValidTo() - epochSeconds)) == NULL) {
        throw std::runtime_error("Unable to set valid to field");
    }

    // set public key
    if ((X509_set_pubkey(cert.get(), key.m_evpPkey)) == 0) {
        throw std::runtime_error("Unable to set public key");
    }

    X509AddEntry(cert, "C", cfg.getCountry());
    X509AddEntry(cert, "ST", cfg.getState());
    X509AddEntry(cert, "L", cfg.getLocality());
    X509AddEntry(cert, "O", cfg.getOrganization());
    X509AddEntry(cert, "OU", cfg.getOrganizationUnit());
    X509AddEntry(cert, "CN", cfg.getCommonName());
    X509AddEntry(cert, "OU", cfg.getEmail());

    // set issuer
    if ((X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()))) == 0) {
        throw std::runtime_error("Unable to set issuer");
    }

    // set ip addresses
    for (const std::string& ip : cfg.getIpList()) {
        addExtension(cert, NID_subject_alt_name, (EXT_IP_TYPE + ip));
    }

    // set dns addresses
    for (const std::string& dns : cfg.getDnsList()) {
        addExtension(cert, NID_subject_alt_name, (EXT_DNS_TYPE + dns));
    }

    // signing certificate
    if (!X509_sign(cert.get(), key.m_evpPkey, EVP_sha256())) {
        throw std::runtime_error("Unable to sign x509 certificate");
    }

    return CertificateX509(std::move(cert));
}

CertificateX509::CertificateX509(X509Ptr cert)
{
    m_x509 = cert.release();

    if (m_x509 == NULL) {
        throw std::runtime_error("Impossible to create certificate");
    }
}

void CertificateX509::importPem(const std::string& certPem)
{
    X509_free(m_x509);

    BIO* bio = BIO_new_mem_buf(static_cast<const void*>(certPem.c_str()), static_cast<int>(certPem.length()));

    if (bio == NULL) {
        throw std::runtime_error("Impossible to read the certificate PEM");
    }

    m_x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (m_x509 == NULL) {
        throw std::runtime_error("Impossible to read the certificate PEM");
    }
}

/* Local helper function */

SerialNumberPtr generateSerialNumber()
{
    // create a bignumber for serial number generation
    BigNumberPtr bn(BN_new(), &BN_free);

    if (bn.get() == NULL) {
        throw std::runtime_error("Unable to allocate big pseudo random number");
    }

    if ((BN_pseudo_rand(bn.get(), SERIAL_RAND_BITS, 0, 0)) != 1) {
        throw std::runtime_error("Unable to generate big pseudo random number");
    }

    SerialNumberPtr serialNumber(BN_to_ASN1_INTEGER(bn.get(), NULL), &ASN1_INTEGER_free);

    if (serialNumber.get() == NULL) {
        throw std::runtime_error("Unable to convert bn to ASN1 integer");
    }

    return std::move(serialNumber);
}

void addExtension(X509Ptr& cert, int nid, const std::string& value)
{
    X509_EXTENSION* ex = X509V3_EXT_conf_nid(NULL, NULL, nid, const_cast<char*>(value.c_str()));

    if (ex == NULL) {
        X509_EXTENSION_free(ex);
        throw std::runtime_error("Unable to set extension");
    }

    X509_add_ext(cert.get(), ex, -1);
    X509_EXTENSION_free(ex);
}

void X509AddEntry(X509Ptr& cert, const std::string& fieldName, const std::string& fieldData)
{
    X509_NAME* certName = X509_get_subject_name(cert.get());

    if ((X509_NAME_add_entry_by_txt(certName, fieldName.c_str(), MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(fieldData.c_str()), -1, -1, 0)) == 0) {
        throw std::runtime_error("Unable to set " + fieldName + " to the value " + fieldData);
    }
}
} // namespace fty
