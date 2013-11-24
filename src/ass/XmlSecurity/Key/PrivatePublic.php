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

use ass\XmlSecurity\Pem;
use ass\XmlSecurity\Key;

use ass\XmlSecurity\Exception\DecryptionException;
use ass\XmlSecurity\Exception\EncryptionException;
use ass\XmlSecurity\Exception\InvalidSignatureException;
use ass\XmlSecurity\Exception\SignatureErrorException;

/**
 * This class holds a security key and provides the necessary encryption,
 * decryption and certificate handling routines.
 *
 * @author Andreas Schamberger <mail@andreass.net>
 * @author Robert Richards <rrichards@cdatazone.org>
 */
abstract class PrivatePublic extends Key
{
    /**
     * Openssl digest.
     *
     * @var string
     */
    protected $digest;

    /**
     * Key type: private/public
     *
     * @var unknown_type
     */
    protected $keyType;

    /**
     * Openssl resource.
     *
     * @var unknown_type
     */
    protected $opensslResource;

    /**
     * Openssl padding.
     *
     * @var unknown_type
     */
    protected $padding;

    /**
     * Passphrase.
     *
     * @var string
     */
    protected $passphrase = '';

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
        if ($isFile) {
            $this->key = file_get_contents($key);
        } else {
            $this->key = $key;
        }
        if (!is_null($passphrase)) {
            $this->passphrase = $passphrase;
        }
        if ($keyType == self::TYPE_PUBLIC) {
            $this->keyType = self::TYPE_PUBLIC;
            $this->opensslResource = openssl_get_publickey($this->key);
        } else {
            $this->keyType = self::TYPE_PRIVATE;
            $this->opensslResource = openssl_get_privatekey($this->key, $this->passphrase);
        }
    }

    /**
     * Decrypt the given data with this key.
     *
     * @param string $data Data to decrypt
     *
     * @return string
     */
    public function decryptData($data)
    {
        if ($this->keyType == self::TYPE_PUBLIC) {
            if (false === openssl_public_decrypt($data, $decrypted, $this->opensslResource, $this->padding)) {
                throw new DecryptionException($this->type, $this->getOpenSslErrorString());
            }
        } else {
            if (false === openssl_private_decrypt($data, $decrypted, $this->opensslResource, $this->padding)) {
                throw new DecryptionException($this->type, $this->getOpenSslErrorString());
            }
        }

        return $decrypted;
    }

    /**
     * Encrypt the given data with this key.
     *
     * @param string $data Data to encrypt
     *
     * @return string
     */
    public function encryptData($data)
    {
        if ($this->keyType == self::TYPE_PUBLIC) {
            if (false === openssl_public_encrypt($data, $encryptedData, $this->opensslResource, $this->padding)) {
                throw new EncryptionException($this->type, $this->getOpenSslErrorString());
            }
        } else {
            if (false === openssl_private_encrypt($data, $encryptedData, $this->opensslResource, $this->padding)) {
                throw new EncryptionException($this->type, $this->getOpenSslErrorString());
            }
        }

        return $encryptedData;
    }

    /**
     * Gets the last error messages from the openSSL library.
     *
     * @return string
     */
    protected function getOpenSslErrorString()
    {
        $errorStrings = array();
        while (false !== ($errorString = openssl_error_string())) {
            $errorStrings[] = $errorString;
        }

        return implode("<br />\n", $errorStrings);
    }

    /**
     * Retrieve the X509 certificate this key represents.
     *
     * Will return the X509 certificate in PEM-format if this key represents
     * an X509 certificate.
     *
     * @param boolean $singleLineString Certificate should be returned in one single line
     *
     * @return string|null
     */
    public function getX509Certificate($singleLineString = false)
    {
        if ($this->keyType != self::TYPE_PUBLIC) {
            return null;
        }
        if ($singleLineString === true) {
            $certs = Pem::parseKeyFromPemFormat($this->key, Pem::PEM_TYPE_CERTIFICATE_X509);

            return (isset($certs[0])) ? $certs[0] : null;
        }

        return $this->key;
    }

    /**
     * Retrieve the key details.
     *
     * @return string|false
     */
    public function getDetails()
    {
        return openssl_pkey_get_details($this->opensslResource);
    }

    /**
     * Gets the X509 subject key identifier for this certificate.
     *
     * @return string|null
     */
    public function getX509SubjectKeyIdentifier()
    {
        if ($this->keyType != self::TYPE_PUBLIC) {
            return null;
        }
        $x509 = openssl_x509_parse($this->key);
        if (!isset($x509['extensions']['subjectKeyIdentifier'])) {
            return null;
        }
        $keyid = explode(':', $x509['extensions']['subjectKeyIdentifier']);
        $data = '';
        foreach ($keyid as $hexchar) {
            $data .= chr(hexdec($hexchar));
        }

        return base64_encode($data);
    }

    /**
     * Get the thumbprint of the X509 certificate this key represents.
     *
     * @return string
     */
    public function getX509Thumbprint()
    {
        if ($this->keyType != self::TYPE_PUBLIC) {
            return null;
        }
        $certs = Pem::parseKeyFromPemFormat($this->key, Pem::PEM_TYPE_CERTIFICATE_X509);

        return strtolower(sha1(base64_decode($certs[0])));
    }

    /**
     * Sign the given data with this key and return signature.
     *
     * @param string $data Data to sign
     *
     * @return string
     */
    public function signData($data)
    {
        if (false === openssl_sign($data, $signature, $this->opensslResource, $this->digest)) {
            throw new SignatureErrorException($this->type, $this->getOpenSslErrorString());
        }

        return $signature;
    }

    /**
     * Verifies the given data with this key.
     *
     * @param string $data      Data which should be signed by signature
     * @param string $signature Signature string
     *
     * @return boolean
     */
    public function verifySignature($data, $signature)
    {
        $resultStatus = openssl_verify($data, $signature, $this->opensslResource, $this->digest);
        if (-1 === $resultStatus) {
            throw new SignatureErrorException($this->type, $this->getOpenSslErrorString());
        } elseif (0 === $resultStatus) {
            throw new InvalidSignatureException($this->type, $this->getOpenSslErrorString());
        }

        return true;
    }
}
