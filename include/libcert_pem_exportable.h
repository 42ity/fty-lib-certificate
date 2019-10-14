/*  =========================================================================
    libcert_pem_exportable - Interface to export PEM

    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of CZMQ, the high-level C binding for 0MQ:
    http://czmq.zeromq.org.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

#ifndef LIBCERT_PEM_EXPORTABLE_H_INCLUDED
#define LIBCERT_PEM_EXPORTABLE_H_INCLUDED

#include <string>

namespace fty
{
    class PemExportable
    {
    public:
        virtual ~PemExportable() = default;
        virtual std::string getPem() const = 0;
    protected:
        PemExportable() = default;
    };

    inline bool operator==(const PemExportable& lhs, const PemExportable& rhs){ return (lhs.getPem() == rhs.getPem()); }
    inline bool operator!=(const PemExportable& lhs, const PemExportable& rhs){ return !(lhs == rhs); }

} // namespace fty

#endif
