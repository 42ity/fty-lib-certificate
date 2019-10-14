/*  =========================================================================
    fty-lib-certificate - generated layer of public API

    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of CZMQ, the high-level C binding for 0MQ:
    http://czmq.zeromq.org.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.

################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
    =========================================================================
*/

#ifndef FTY_LIB_CERTIFICATE_LIBRARY_H_INCLUDED
#define FTY_LIB_CERTIFICATE_LIBRARY_H_INCLUDED

//  Set up environment for the application

//  External dependencies
#include <openssl/sha.h>
#include <cxxtools/allocator.h>

//  FTY_LIB_CERTIFICATE version macros for compile-time API detection
#define FTY_LIB_CERTIFICATE_VERSION_MAJOR 1
#define FTY_LIB_CERTIFICATE_VERSION_MINOR 0
#define FTY_LIB_CERTIFICATE_VERSION_PATCH 0

#define FTY_LIB_CERTIFICATE_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define FTY_LIB_CERTIFICATE_VERSION \
    FTY_LIB_CERTIFICATE_MAKE_VERSION(FTY_LIB_CERTIFICATE_VERSION_MAJOR, FTY_LIB_CERTIFICATE_VERSION_MINOR, FTY_LIB_CERTIFICATE_VERSION_PATCH)

// czmq_prelude.h bits
#if !defined (__WINDOWS__)
#   if (defined WIN32 || defined _WIN32 || defined WINDOWS || defined _WINDOWS)
#       undef __WINDOWS__
#       define __WINDOWS__
#   endif
#endif

// Windows MSVS doesn't have stdbool
#if (defined (_MSC_VER) && !defined (true))
#   if (!defined (__cplusplus) && (!defined (true)))
#       define true 1
#       define false 0
        typedef char bool;
#   endif
#else
#   include <stdbool.h>
#endif
// czmq_prelude.h bits

#if defined (__WINDOWS__)
#   if defined FTY_LIB_CERTIFICATE_STATIC
#       define FTY_LIB_CERTIFICATE_EXPORT
#   elif defined FTY_LIB_CERTIFICATE_INTERNAL_BUILD
#       if defined DLL_EXPORT
#           define FTY_LIB_CERTIFICATE_EXPORT __declspec(dllexport)
#       else
#           define FTY_LIB_CERTIFICATE_EXPORT
#       endif
#   elif defined FTY_LIB_CERTIFICATE_EXPORTS
#       define FTY_LIB_CERTIFICATE_EXPORT __declspec(dllexport)
#   else
#       define FTY_LIB_CERTIFICATE_EXPORT __declspec(dllimport)
#   endif
#   define FTY_LIB_CERTIFICATE_PRIVATE
#elif defined (__CYGWIN__)
#   define FTY_LIB_CERTIFICATE_EXPORT
#   define FTY_LIB_CERTIFICATE_PRIVATE
#else
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define FTY_LIB_CERTIFICATE_PRIVATE __attribute__ ((visibility ("hidden")))
#       define FTY_LIB_CERTIFICATE_EXPORT __attribute__ ((visibility ("default")))
#   else
#       define FTY_LIB_CERTIFICATE_PRIVATE
#       define FTY_LIB_CERTIFICATE_EXPORT
#   endif
#endif

//  Project has no stable classes, so we build the draft API
#undef  FTY_LIB_CERTIFICATE_BUILD_DRAFT_API
#define FTY_LIB_CERTIFICATE_BUILD_DRAFT_API

//  Opaque class structures to allow forward references
//  These classes are stable or legacy and built in all releases
//  Draft classes are by default not built in stable releases
#ifdef FTY_LIB_CERTIFICATE_BUILD_DRAFT_API
typedef struct _libcert_pem_exportable_t libcert_pem_exportable_t;
#define LIBCERT_PEM_EXPORTABLE_T_DEFINED
typedef struct _libcert_certificate_x509_t libcert_certificate_x509_t;
#define LIBCERT_CERTIFICATE_X509_T_DEFINED
typedef struct _libcert_public_key_t libcert_public_key_t;
#define LIBCERT_PUBLIC_KEY_T_DEFINED
typedef struct _libcert_keys_t libcert_keys_t;
#define LIBCERT_KEYS_T_DEFINED
#endif // FTY_LIB_CERTIFICATE_BUILD_DRAFT_API


//  Public classes, each with its own header file
#ifdef FTY_LIB_CERTIFICATE_BUILD_DRAFT_API
#include "libcert_pem_exportable.h"
#include "libcert_certificate_X509.h"
#include "libcert_public_key.h"
#include "libcert_keys.h"
#endif // FTY_LIB_CERTIFICATE_BUILD_DRAFT_API

#ifdef FTY_LIB_CERTIFICATE_BUILD_DRAFT_API

#ifdef __cplusplus
extern "C" {
#endif

//  Self test for private classes
FTY_LIB_CERTIFICATE_EXPORT void
    fty_lib_certificate_private_selftest (bool verbose, const char *subtest);

#ifdef __cplusplus
}
#endif
#endif // FTY_LIB_CERTIFICATE_BUILD_DRAFT_API

#endif
/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/
