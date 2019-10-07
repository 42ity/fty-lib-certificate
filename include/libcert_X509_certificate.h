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

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new libcert_x509_certificate
FTY_LIB_CERTIFICATE_EXPORT libcert_x509_certificate_t *
    libcert_x509_certificate_new (void);

//  Destroy the libcert_x509_certificate
FTY_LIB_CERTIFICATE_EXPORT void
    libcert_x509_certificate_destroy (libcert_x509_certificate_t **self_p);

//  Self test of this class
FTY_LIB_CERTIFICATE_EXPORT void
    libcert_x509_certificate_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
