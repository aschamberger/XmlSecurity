<?php
/**
 * This file is part of the XmlSecurity library. It is a library written in PHP
 * for working with XML Encryption and Signatures.
 *
 * Large portions of the library are derived from the xmlseclibs PHP library for
 * XML Security (http://code.google.com/p/xmlseclibs/) Copyright (c) 2007-2010,
 * Robert Richards <rrichards@cdatazone.org>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author  Andreas Schamberger <mail@andreass.net>
 * @author  Robert Richards <rrichards@cdatazone.org>
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 */

namespace ass\XmlSecurity\Key;

/**
 * This class holds a security key and provides the necessary encryption,
 * decryption and certificate handling routines.
 *
 * @author Andreas Schamberger <mail@andreass.net>
 */
class RsaSha1 extends PrivatePublic
{
    /**
     * Loads the given cryptographic key for the class.
     *
     * @param string  $keyType    \ass\XmlSecurity\Key::TYPE_PUBLIC | \ass\XmlSecurity\Key::TYPE_PRIVATE
     * @param string  $key        Key string or filename
     * @param boolean $isFile     Is parameter key a filename
     * @param string  $passphrase Passphrase for given key
     */
    public function __construct($keyType, $key, $isFile = false, $passphrase = null)
    {
        $this->digest  = OPENSSL_ALGO_SHA1;
        $this->padding = OPENSSL_PKCS1_PADDING;
        $this->type    = self::RSA_SHA1;
        parent::__construct($keyType, $key, $isFile, $passphrase);
    }
}
