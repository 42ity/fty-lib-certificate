/*  =========================================================================
    libcert_crypto - List of helper functions use a bit everywhere

    Copyright (C) 2014 - 2020 Eaton

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

#ifndef LIBCERT_CRYPTO_H_INCLUDED
#define LIBCERT_CRYPTO_H_INCLUDED

namespace fty
{
    /**
     * Encrypt a string
     * @param plainData Plain Text Input
     * @param passphrase Pass phrase
     * @return The Plain text encrypted
     */
    std::string encrypt(const std::string& plainData, const std::string& passphrase);

    /**
     * Decrypt a string
     * @param encryptedData The encrypted data
     * @param passphrase Pass phrase
     * @return The Plain text decrypted
     */
    std::string decrypt(const std::string& encryptedData, const std::string& passphrase);
  
    /**
     * Check pass phraseFormat
     * @param phassphrase
     * @return True if the passphrase is Ok, otherwise false. 
     */
    bool checkPassphraseFormat(const std::string& phassphrase);
    
    /**
     * Get passphrase format
     * @param phassphrase
     * @return The passphrase format
     */
    std::string getPassphraseFormat();

} //namespace fty

#endif
