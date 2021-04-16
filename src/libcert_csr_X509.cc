/*  =========================================================================
    libcert_csr_X509 - X509 Certificate signing request

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
    libcert_csr_x509 - X509 Certificate signing request
@discuss
@end
*/

#include "libcert_csr_X509.h"
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

/* Local helper function definitions */
static void addExtension(STACK_OF(X509_EXTENSION) * sk, int nid, const std::string& value);
static void X509AddEntry(X509ReqPtr& csr, const std::string& fieldName, const std::string& fieldData);

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

CsrX509::CsrX509(const std::string& csrPem)
{
    importPem(csrPem);
}

CsrX509::CsrX509(const CsrX509& x509Req)
{
    importPem(x509Req.getPem());
}

CsrX509::~CsrX509()
{
    // Cleanup
    X509_REQ_free(m_x509Req);
}

std::string CsrX509::getSubject() const
{
    char* str = X509_NAME_oneline(X509_REQ_get_subject_name(m_x509Req), NULL, 0);

    std::string returnValue(str);

    free(str);

    return returnValue;
}

std::string CsrX509::getDetails() const
{
    BIO*        bioOut = BIO_new(BIO_s_mem());
    std::string details;

    X509_REQ_print(bioOut, m_x509Req);

    BUF_MEM* bioBuffer;
    BIO_get_mem_ptr(bioOut, &bioBuffer);
    details = std::string(bioBuffer->data, bioBuffer->length);

    BIO_free(bioOut);

    return details;
}

std::string CsrX509::getPem() const
{
    BIO*        bioOut = BIO_new(BIO_s_mem());
    std::string pem;

    PEM_write_bio_X509_REQ(bioOut, m_x509Req);

    BUF_MEM* bioBuffer;
    BIO_get_mem_ptr(bioOut, &bioBuffer);
    pem = std::string(bioBuffer->data, bioBuffer->length);

    BIO_free(bioOut);

    return pem;
}

PublicKey CsrX509::getPublicKey() const
{
    return PublicKey(X509_REQ_get_pubkey(m_x509Req));
}

CsrX509 CsrX509::generateCsr(const Keys& key, const CertificateConfig& cfg)
{
    // generate new X509 signing request
    X509ReqPtr csr(X509_REQ_new(), &X509_REQ_free);

    if (csr.get() == NULL) {
        throw std::runtime_error("Impossible to create sign request");
    }

    // set version (version number - 1)
    if ((X509_REQ_set_version(csr.get(), cfg.getVersion() - 1)) == 0) {
        throw std::runtime_error("Unable to set sign request version");
    }

    // set public key
    if ((X509_REQ_set_pubkey(csr.get(), key.m_evpPkey)) == 0) {
        throw std::runtime_error("Unable to set public key");
    }

    X509AddEntry(csr, "C", cfg.getCountry());
    X509AddEntry(csr, "ST", cfg.getState());
    X509AddEntry(csr, "L", cfg.getLocality());
    X509AddEntry(csr, "O", cfg.getOrganization());
    X509AddEntry(csr, "OU", cfg.getOrganizationUnit());
    X509AddEntry(csr, "CN", cfg.getCommonName());
    X509AddEntry(csr, "OU", cfg.getEmail());

    // allocate extension stack
    STACK_OF(X509_EXTENSION)* extStack = sk_X509_EXTENSION_new_null();

    if (extStack == NULL) {
        throw std::runtime_error("Unable to allocate exetension stack");
    }

    // set ip addresses
    for (const std::string& ip : cfg.getIpList()) {
        addExtension(extStack, NID_subject_alt_name, (EXT_IP_TYPE + ip));
    }

    // set dns addresses
    for (const std::string& dns : cfg.getDnsList()) {
        addExtension(extStack, NID_subject_alt_name, (EXT_DNS_TYPE + dns));
    }

    // add exetensions to csr
    X509_REQ_add_extensions(csr.get(), extStack);
    sk_X509_EXTENSION_pop_free(extStack, X509_EXTENSION_free);

    // // signing request
    if (!X509_REQ_sign(csr.get(), key.m_evpPkey, EVP_sha256())) {
        throw std::runtime_error("Unable to sign x509 csr");
    }

    return CsrX509(std::move(csr));
}

CsrX509::CsrX509(X509ReqPtr csr)
{
    m_x509Req = csr.release();

    if (m_x509Req == NULL) {
        throw std::runtime_error("Impossible to create csr");
    }
}

void CsrX509::importPem(const std::string& certPem)
{
    X509_REQ_free(m_x509Req);

    BIO*        bio = BIO_new_mem_buf(static_cast<const void*>(certPem.c_str()), static_cast<int>(certPem.length()));

    if (bio == NULL) {
        throw std::runtime_error("Impossible to read the csr PEM");
    }

    m_x509Req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (m_x509Req == NULL) {
        throw std::runtime_error("Impossible to read the csr PEM");
    }
}

/* Local helper function */

void addExtension(STACK_OF(X509_EXTENSION) * sk, int nid, const std::string& value)
{
    if (sk == NULL) {
        throw std::runtime_error("Unable to get extension stack");
    }

    X509_EXTENSION* ex = X509V3_EXT_conf_nid(NULL, NULL, nid, const_cast<char*>(value.c_str()));
    if (!ex) {
        X509_EXTENSION_free(ex);
        throw std::runtime_error("Unable to set extension");
    }

    sk_X509_EXTENSION_push(sk, ex);
}

void X509AddEntry(X509ReqPtr& csr, const std::string& fieldName, const std::string& fieldData)
{
    X509_NAME* subjectName = X509_REQ_get_subject_name(csr.get());

    if ((X509_NAME_add_entry_by_txt(subjectName, fieldName.c_str(), MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(fieldData.c_str()), -1, -1, 0)) == 0) {
        throw std::runtime_error("Unable to set " + fieldName + " to the value " + fieldData);
    }
}
} // namespace fty
