/*  =========================================================================
    libcert_pem_exportable - Abstract class for generic PEM exportable class

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
