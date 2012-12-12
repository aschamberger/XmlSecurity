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

namespace ass\XmlSecurity;

use ass\XmlSecurity\Exception\InvalidArgumentException;

/**
 * This class provides methods to encrypt XML documents and implements the
 * 'XML Encryption Syntax and Processing' standard.
 *
 * @author Andreas Schamberger <mail@andreass.net>
 * @author Robert Richards <rrichards@cdatazone.org>
 * @see    http://www.w3.org/TR/xmlenc-core/
 */
class Enc
{
    /**
     * Web Services Security Utility namespace.
     */
    const NS_WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    /**
     * XML Encryption Syntax and Processing namespace.
     */
    const NS_XMLENC = 'http://www.w3.org/2001/04/xmlenc#';

    /**
     * Web Services Security Utility namespace prefix.
     */
    const PFX_WSU = 'wsu';

    /**
     * XML Encryption Syntax and Processing prefix.
     */
    const PFX_XMLENC = 'xenc';

    /**
     * Encryption type 'CONTENT'.
     */
    const CONTENT = 'http://www.w3.org/2001/04/xmlenc#Content';

    /**
     * Encryption type 'ELEMENT'.
     */
    const ELEMENT = 'http://www.w3.org/2001/04/xmlenc#Element';

    /**
     * ds:RetrievalMethod type for encrypted keys.
     */
    const RETRIEVAL_METHOD_ENCRYPTED_KEY = 'http://www.w3.org/2001/04/xmlenc#EncryptedKey';

    /**
     * Creates a new EncryptedKey node and appends it to the given node.
     *
     * @param string               $guid             Unique id
     * @param \ass\XmlSecurity\Key $keyToBeEncrypted Key that should be encrypted
     * @param \ass\XmlSecurity\Key $keyForEncryption Key to use for encryption
     * @param \DOMNode             $appendTo         Node where encrypted key should be appenden
     * @param \DOMNode             $insertBefore     Encrypted key should be inserted before this node
     * @param \DOMElement          $keyInfo          KeyInfo element
     *
     * @return \DOMElement
     */
    public static function createEncryptedKey($guid, \ass\XmlSecurity\Key $keyToBeEncrypted, \ass\XmlSecurity\Key $keyForEncryption, \DOMNode $appendTo, \DOMNode $insertBefore = null, \DOMElement $keyInfo = null)
    {
        $doc = $appendTo->ownerDocument;
        $encryptedKey = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':EncryptedKey');
        $encryptedKey->setAttribute('Id', $guid);

        if (!is_null($insertBefore)) {
            $appendTo->insertBefore($encryptedKey, $insertBefore);
        } else {
            $appendTo->appendChild($encryptedKey);
        }

        $encryptionMethod = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':EncryptionMethod');
        $encryptionMethod->setAttribute('Algorithm', $keyForEncryption->getAlgorithm());
        $encryptedKey->appendChild($encryptionMethod);

        if (!is_null($keyInfo)) {
            $encryptedKey->appendChild($keyInfo);
        }

        $cipherData = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':CipherData');
        $encryptedKey->appendChild($cipherData);

        $encryptedKeyString = base64_encode($keyForEncryption->encryptData($keyToBeEncrypted->getKey()));

        $cipherValue = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':CipherValue', $encryptedKeyString);
        $cipherData->appendChild($cipherValue);

        return $encryptedKey;
    }

    /**
     * Creates a new ReferenceList Node and appends it to the given node.
     *
     * @param \DOMElement $appendTo Appent the reference list to this node
     *
     * @return \DOMElement
     */
    public static function createReferenceList(\DOMElement $appendTo)
    {
        $doc = $appendTo->ownerDocument;
        $referenceList = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':ReferenceList');
        $appendTo->appendChild($referenceList);

        return $referenceList;
    }

    /**
     * Decrypts the EncryptedKey and returns a \ass\XmlSecurity\Key instance.
     *
     * Uses either the given key or resolves the KeyInfo data.
     *
     * @param \DOMElement          $encryptedKey Encrypted key element
     * @param \ass\XmlSecurity\Key $keyToDecrypt Key used for decryption
     *
     * @return string|null
     */
    public static function decryptEncryptedKey(\DOMElement $encryptedKey, \ass\XmlSecurity\Key $keyToDecrypt = null)
    {
        if (is_null($keyToDecrypt)) {
            $keyToDecrypt = self::getSecurityKey($encryptedKey);
        }
        $encryptionMethod = $encryptedKey->getElementsByTagNameNS(self::NS_XMLENC, 'EncryptionMethod')->item(0);
        if (!is_null($encryptionMethod)) {
            $algorithm = $encryptionMethod->getAttribute('Algorithm');
            $cipherValue = $encryptedKey->getElementsByTagNameNS(self::NS_XMLENC, 'CipherValue')->item(0);
            if (!is_null($cipherValue)) {
                return $keyToDecrypt->decryptData(base64_decode($cipherValue->nodeValue));
            }
        }

        return null;
    }

    /**
     * Decrypts the given node.
     *
     * Uses either the given key or resolves the KeyInfo data.
     *
     * @param \DOMNode             $node Node to decrypt
     * @param \ass\XmlSecurity\Key $key  Key to use for decryption
     *
     * @return \DOMNode|null
     */
    public static function decryptNode(\DOMNode $node, $key = null)
    {
        if ($node instanceof \DOMDocument) {
            $doc = $node;
            $encryptedData = $node->documentElement->getElementsByTagNameNS(self::NS_XMLENC, 'EncryptedData')->item(0);
        } else {
            $doc = $node->ownerDocument;
            $encryptedData = $node;
        }
        if (!is_null($encryptedData)) {
            if (is_null($key)) {
                $key = self::getSecurityKey($encryptedData);
            }
            $type = $encryptedData->getAttribute('Type');
            $cipherValue = $encryptedData->getElementsByTagNameNS(self::NS_XMLENC, 'CipherValue')->item(0);
            $encryptionMethod = $encryptedData->getElementsByTagNameNS(self::NS_XMLENC, 'EncryptionMethod')->item(0);
            $encryptionAlgorithm = $algorithm = $encryptionMethod->getAttribute('Algorithm');
            if (!is_null($cipherValue)) {
                $decryptedDataString = $key->decryptData(base64_decode($cipherValue->nodeValue));
                // replace nodes
                switch ($type) {
                    case self::ELEMENT:
                        if ($node instanceof \DOMDocument) {
                            $node = new \DOMDocument();
                            $node->loadXML($decryptedDataString);
                        } else {
                            $documentFragment = $doc->createDocumentFragment();
                            $documentFragment->appendXML($decryptedDataString);
                            $node->parentNode->replaceChild($documentFragment, $node);
                            $node = $documentFragment;
                        }
                        break;
                    case self::CONTENT:
                        $documentFragment = $doc->createDocumentFragment();
                        $documentFragment->appendXML($decryptedDataString);
                        if ($node instanceof \DOMDocument) {
                            $node->documentElement->replaceChild($documentFragment, $node->documentElement->firstChild);
                        } else {
                            $node->parentNode->replaceChild($documentFragment, $node);
                        }
                        $node = $documentFragment;
                        break;
                }
            } else {
                return null;
            }
        }

        return $node;
    }

    /**
     * Encryptes the given node and adds it to the list of references.
     *
     * @param \DOMNode             $node          DOM node to encrypt
     * @param string               $type          \ass\XmlSecurity\Enc::ELEMENT || \ass\XmlSecurity\Enc::CONTENT
     * @param \ass\XmlSecurity\Key $key           Security key to use for encryption
     * @param \DOMElement          $referenceList Reference list element
     * @param \DOMElement          $keyInfo       KeyInfo element
     *
     * @return \DOMNode
     */
    public static function encryptNode(\DOMNode $node, $type, \ass\XmlSecurity\Key $key, \DOMElement $referenceList = null, $keyInfo = null)
    {
        if ($type != self::ELEMENT && $type != self::CONTENT) {
            throw InvalidArgumentException('type', 'Value must be either \ass\XmlSecurity\Enc::CONTENT or \ass\XmlSecurity\Enc::ELEMENT');
        }
        if ($node instanceof \DOMDocument) {
            $doc = $node;
        } else {
            $doc = $node->ownerDocument;
        }
        $uri = 'Id-' . \ass\XmlSecurity\DSig::generateUUID();

        $encryptedData = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':EncryptedData');
        $encryptedData->setAttribute("Id", $uri);
        $cipherData = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':CipherData');
        $encryptedData->appendChild($cipherData);
        $cipherValue = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':CipherValue');
        $cipherData->appendChild($cipherValue);

        $dataToEncrypt = '';
        switch ($type) {
            case self::ELEMENT:
                $dataToEncrypt = $doc->saveXML($node);
                $encryptedData->setAttribute('Type', self::ELEMENT);
                break;
            case self::CONTENT:
                foreach ($node->childNodes as $child) {
                    $dataToEncrypt .= $doc->saveXML($child);
                }
                $encryptedData->setAttribute('Type', self::CONTENT);
                break;
        }

        $encryptionMethod = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':EncryptionMethod');
        $encryptionMethod->setAttribute('Algorithm', $key->getAlgorithm());
        $encryptedData->insertBefore($encryptionMethod, $cipherData);

        if (!is_null($keyInfo)) {
            $encryptedData->insertBefore($keyInfo, $cipherData);
        }

        $encryptedDataString = base64_encode($key->encryptData($dataToEncrypt));
        $value = $doc->createTextNode($encryptedDataString);
        $cipherValue->appendChild($value);

        // replace nodes
        switch ($type) {
            case self::ELEMENT:
                if ($node instanceof \DOMDocument) {
                    $node->replaceChild($encryptedData, $node->documentElement);
                } else {
                    $node->parentNode->replaceChild($encryptedData, $node);
                }
                break;
            case self::CONTENT:
                while ($node->firstChild) {
                    $node->removeChild($node->firstChild);
                }
                $node->appendChild($encryptedData);
                break;
        }

        if (!is_null($referenceList)) {
            $dataReference = $doc->createElementNS(self::NS_XMLENC, self::PFX_XMLENC . ':DataReference');
            $dataReference->setAttribute('URI', '#' . $uri);
            $referenceList->appendChild($dataReference);
        }

        return $node;
    }

    /**
     * Gets the security referenced in the given $encryptedData element.
     *
     * You can add your own key resolver by calling:
     * $ns = 'myns';
     * $localname = 'MyKeyInfo';
     * $keyResolver = array('MyClass' => 'function');
     * \ass\XmlSecurity\DSig::addKeyInfoResolver($ns, $localName, $keyResolver);
     *
     * @param \DOMElement $encryptedData Encrypted data element
     *
     * @return \ass\XmlSecurity\Key|null
     */
    public static function getSecurityKey(\DOMElement $encryptedData)
    {
        $encryptedMethod = $encryptedData->getElementsByTagNameNS(self::NS_XMLENC, 'EncryptionMethod')->item(0);
        if (!is_null($encryptedMethod)) {
            $algorithm = $encryptedMethod->getAttribute('Algorithm');
            $keyInfo = $encryptedData->getElementsByTagNameNS(\ass\XmlSecurity\DSig::NS_XMLDSIG, 'KeyInfo')->item(0);
            if (!is_null($keyInfo)) {
                return \ass\XmlSecurity\DSig::getSecurityKeyFromKeyInfo($keyInfo, $algorithm);
            }
        }

        return null;
    }

    /**
     * Locates EncryptedData elements within the given node or referenceList.
     *
     * @param \DOMNode    $node          Node where encrypted data should be located
     * @param \DOMElement $referenceList Reference list element
     *
     * @return \DOMNodeList
     */
    public static function locateEncryptedData(\DOMNode $node, \DOMElement $referenceList = null)
    {
        if ($node instanceof \DOMDocument) {
            $doc = $node;
            $relativeTo = null;
        } else {
            $doc = $node->ownerDocument;
            $relativeTo = $node;
        }
        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('xenc', self::NS_XMLENC);
        if (!is_null($referenceList)) {
            $query = array();
            foreach ($referenceList->childNodes as $dataReference) {
                $url = parse_url($dataReference->getAttribute('URI'));
                $referenceId = $url['fragment'];
                $query[] = '//*[@Id="' . $referenceId . '"]';
            }
            $query = implode(' | ', $query);
        } else {
            $query = './/xenc:EncryptedData';
        }
        $nodes = $xpath->query($query);
        if ($nodes->length > 0) {
            return $nodes;
        }

        return null;
    }

    /**
     * Locates the 'xenc:EncryptedKey' within the given \DOMDocument or \DOMNode.
     *
     * @param \DOMNode $node Node where encrypted key should be located
     *
     * @return \DOMElement
     */
    public static function locateEncryptedKey(\DOMNode $node)
    {
        if ($node instanceof \DOMDocument) {
            $doc = $node;
            $relativeTo = null;
        } else {
            $doc = $node->ownerDocument;
            $relativeTo = $node;
        }
        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('xenc', self::NS_XMLENC);
        $query = './/xenc:EncryptedKey';
        $nodes = $xpath->query($query, $relativeTo);
        if ($nodes->length > 0) {
            return $nodes->item(0);
        }

        return null;
    }

    /**
     * Locates the 'xenc:ReferenceList' within the given \DOMDocument or \DOMNode.
     *
     * @param \DOMNode $node Node where reference list should be located
     *
     * @return \DOMElement
     */
    public static function locateReferenceList(\DOMNode $node)
    {
        if ($node instanceof \DOMDocument) {
            $doc = $node;
            $relativeTo = null;
        } else {
            $doc = $node->ownerDocument;
            $relativeTo = $node;
        }
        $xpath = new \DOMXPath($doc);
        $xpath->registerNamespace('xenc', self::NS_XMLENC);
        $query = './/xenc:ReferenceList';
        $nodes = $xpath->query($query, $relativeTo);
        if ($nodes->length > 0) {
            return $nodes->item(0);
        }

        return null;
    }
}
