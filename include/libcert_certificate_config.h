/*  =========================================================================
    libcert_x509_csr - X509 Certificate signing request

    Copyright (C) 2014 - 2019 Eaton

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

#ifndef LIBCERT_CERT_CONFIG_INCLUDED
#define LIBCERT_CERT_CONFIG_INCLUDED

#include <cstdint>
#include <string>
#include <list>


namespace fty
{
    class CertificateConfig
    {
        public:
            CertificateConfig();

            const uint8_t                & getVersion()          const { return m_version; }
            const uint64_t               & getValidFrom()        const { return m_validFrom; }
            const uint64_t               & getValidTo()          const { return m_validTo; }
            const std::string            & getCountry()          const { return m_country; }
            const std::string            & getState()            const { return m_state; }
            const std::string            & getLocality()         const { return m_locality; }
            const std::string            & getOrganization()     const { return m_organization; }
            const std::string            & getOrganizationUnit() const { return m_organizationUnit; }
            const std::string            & getCommonName()       const { return m_commonName; }
            const std::string            & getEmail()            const { return m_email; }
            const std::list<std::string> & getIpList()           const { return m_ipList; }
            const std::list<std::string> & getDnsList()          const { return m_dnsList; }
            
            void getVersion(const uint8_t &v)                    { m_version = v; }
            void getValidFrom(const uint64_t &v)                 { m_validFrom = v; }
            void getValidTo(const uint64_t &v)                   { m_validTo = v; }
            void getCountry(const std::string &v)                { m_country = v; }
            void getState(const std::string &v)                  { m_state = v; }
            void getLocality(const std::string &v)               { m_locality = v; }
            void getOrganization(const std::string &v)           { m_organization = v; }
            void getOrganizationUnit(const std::string &v)       { m_organizationUnit = v; }
            void getCommonName(const std::string &v)             { m_commonName = v; }
            void getEmail(const std::string &v)                  { m_email = v; }
            void getIpList(const std::list<std::string> &v)      { m_ipList = v; }
            void getDnsList(const std::list<std::string> &v)     { m_dnsList = v; }

        private:
            // V1
            uint8_t                 m_version;
            uint64_t                m_validFrom;
            uint64_t                m_validTo;
            // subject
            std::string             m_country;
            std::string             m_state;
            std::string             m_locality;
            std::string             m_organization;
            std::string             m_organizationUnit;
            std::string             m_commonName;
            std::string             m_email;

            std::list<std::string>  m_ipList;
            std::list<std::string>  m_dnsList;
    };
}

void libcert_certificate_config_test (bool verbose);

#endif