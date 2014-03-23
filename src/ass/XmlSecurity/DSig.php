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

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;

use ass\XmlSecurity\Exception\InvalidArgumentException;
use ass\XmlSecurity\Exception\MissingMandatoryParametersException;

/**
 * This class provides methods to digitally sign XML documents and implements
 * the 'XML Signature Syntax and Processing (Second Edition)' standard.
 *
 * @author Andreas Schamberger <mail@andreass.net>
 * @author Robert Richards <rrichards@cdatazone.org>
 * @see    http://www.w3.org/TR/xmldsig-core/
 */
class DSig
{
    /**
     * XML Signature Syntax and Processing (Second Edition) namespace.
     */

    const NS_XMLDSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * XML Signature Syntax and Processing (Second Edition) prefix.
     */
    const PFX_XMLDSIG = 'ds';

    /**
     * Message Digest algorithm SHA1
     */
    const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';

    /**
     * Message Digest algorithm SHA256
     */
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

    /**
     * Message Digest algorithm SHA256
     */
    const SHA256_DSIG = 'http://www.w3.org/2001/04/xmldsig-more#sha256';

    /**
     * Message Digest algorithm SHA384
     */
    const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';

    /**
     * Message Digest algorithm SHA512
     */
    const SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#sha512';

    /**
     * Enveloped-Signature Transformation Algorithm
     *
     * @link http://www.w3.org/TR/xmldsig-core/#sec-EnvelopedSignature
     */
    const TRANSFORMATION_ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * Message Digest algorithm RIPEMD160
     */
    const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    /**
     * Canonical XML (omits comments)
     */
    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    /**
     * Canonical XML with comments
     */
    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';

    /**
     * Exclusive XML Canonicalization (omits comments)
     */
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    /**
     * Exclusive XML Canonicalization with Comments
     */
    const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    /**
     * XPATH transformation.
     */
    const XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';

    /**
     * List of KeyInfo resolvers that return the desired \ass\XmlSecurity\Key.
     *
     * @var array(string=>array(string=>callable))
     */
    protected static $keyInfoResolvers = array(
        self::NS_XMLDSIG => array(
            'KeyValue' => array(
                __CLASS__,
                'keyInfoKeyValueResolver',
            ),
            'X509Data' => array(
                __CLASS__,
                'keyInfoX509DataResolver',
            ),
        ),
    );

    /**
     * Adds the given key resolver to the list of key resolvers.
     *
     * @param string   $ns          Namespace of KeyInfo
     * @param string   $localName   Name of identifying XML tag
     * @param callable $keyResolver Callback that return XML security key
     *
     * @return null
     */
    public static function addKeyInfoResolver($ns, $localName, $keyResolver)
    {
        self::$keyInfoResolvers[$ns][$localName] = $keyResolver;

        return null;
    }

    /**
     * Adds the given node to the list of signed nodes.
     *
     * <code>
     * $options = array(
     *     'id_name'               => 'Id', // Id attribute name
     *     'id_ns_prefix'          => 'wsu', // namespace prefix for 'Id' attribute
     *     'id_prefix_ns'          => 'http://...', // namespace for 'Id' attribute
     *     'overwrite_id'          => true, // overwrite existing id attribute
     *     'xpath_transformation' => array(
     *         'query' => 'not(ancestor-or-self::dsig:Signature)',
     *         'namespaces' => array(
     *             'dsig' => 'http://...',
     *             'ns2'  => 'http://',
     *         ),
     *     ),
     *     'inclusive_namespaces' => array(
     *         'SOAP-ENV',
     *         'dsig'
     *         '#default'
     *     ),
     * );
     * </code>
     *
     * @param DOMElement $signature               Signature element
     * @param DOMNode    $node                    Node to add to signature
     * @param string     $digestAlgorithm         Digest algorithm
     * @param string     $transformationAlgorithm Transformation algorithm
     * @param array      $options                 Options (id_name, id_ns_prefix, id_prefix_ns, overwrite_id, xpath_transformation, inclusive_namespaces, force_uri)
     *
     * @return DOMElement
     */
    public static function addNodeToSignature(DOMElement $signature, DOMNode $node, $digestAlgorithm, $transformationAlgorithm, array $options = array())
    {
        $doc = $signature->ownerDocument;
        $signedInfo = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'SignedInfo')->item(0);

        $idName = 'Id';
        if (isset($options['id_name'])) {
            $idName = $options['id_name'];
        }
        $idNamespace = null;
        if (isset($options['id_ns_prefix']) && isset($options['id_prefix_ns'])) {
            $idName = $options['id_ns_prefix'] . ':' . $idName;
            $idNamespace = $options['id_prefix_ns'];
        }
        $overwriteId = true;
        if (isset($options['overwrite_id'])) {
            $overwriteId = (bool) $options['overwrite_id'];
        }
        $forceUri = false;
        if (isset($options['force_uri'])) {
            $forceUri = (bool) $options['force_uri'];
        }

        $uri = null;
        if ($node instanceof DOMElement) {
            $idAttributeValue = null;
            if ($overwriteId === false) {
                $idAttributeValue = $node->getAttributeNS($idNamespace, $idName);
            }
            if (empty($idAttributeValue)) {
                $idAttributeValue = 'Id-' . self::generateUUID();
                $node->setAttributeNS($idNamespace, $idName, $idAttributeValue);
            }
            $uri = '#' . $idAttributeValue;
        }

        $reference = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':Reference');
        if (!is_null($uri)) {
            $reference->setAttribute('URI', $uri);
        } elseif ($forceUri === true) {
            $reference->setAttribute('URI', '');
        }
        $signedInfo->appendChild($reference);

        $transforms = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':Transforms');
        $reference->appendChild($transforms);

        $transform = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':Transform');
        $transform->setAttribute('Algorithm', $transformationAlgorithm);
        $transforms->appendChild($transform);

        if ($transformationAlgorithm == self::XPATH && isset($options['xpath_transformation'])) {
            $xpath = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':XPath', $options['xpath_transformation']['query']);
            foreach ($options['xpath_transformation']['namespaces'] as $prefix => $value) {
                $xpath->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:' . $prefix, $value);
            }
            $transform->appendChild($xpath);
        } elseif (($transformationAlgorithm == self::EXC_C14N || $transformationAlgorithm == self::EXC_C14N_COMMENTS) && isset($options['inclusive_namespaces'])) {
            $inclusiveNamespaces = $doc->createElementNS(self::EXC_C14N, 'es:InclusiveNamespaces');
            $inclusiveNamespaces->setAttributeNS(self::EXC_C14N, 'PrefixList', implode(' ', $options['inclusive_namespaces']));
            $transform->appendChild($inclusiveNamespaces);
        }

        $digestMethod = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':DigestMethod');
        $digestMethod->setAttribute('Algorithm', $digestAlgorithm);
        $reference->appendChild($digestMethod);

        $transformedData = self::processTransform($node, $transformationAlgorithm, $options);
        $digestValueString = self::calculateDigest($transformedData, $digestAlgorithm);
        $digestValue = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':DigestValue', $digestValueString);
        $reference->appendChild($digestValue);

        return $reference;
    }

    /**
     * Calculates the digest of the given data with the desired algorithm.
     *
     * @param string $data            Data to calculate digest from
     * @param string $digestAlgorithm Digest algorithm
     *
     * @return string
     */
    private static function calculateDigest($data, $digestAlgorithm)
    {
        switch ($digestAlgorithm) {
            case self::SHA1:
                $algorithm = 'sha1';
                break;
            case self::SHA256:
            case self::SHA256_DSIG:
                $algorithm = 'sha256';
                break;
            case self::SHA384:
                $algorithm = 'sha384';
                break;
            case self::SHA512:
                $algorithm = 'sha512';
                break;
            case self::RIPEMD160:
                $algorithm = 'ripemd160';
                break;
            default:
                throw new InvalidArgumentException('digestAlgorithm', "Invalid digest algorithm given: {$digestAlgorithm}");
        }

        return base64_encode(hash($algorithm, $data, true));
    }

    /**
     * Cananicalizes the given node with the desired algorithm.
     *
     * @param DOMNode $node                      DOMNode to canonicalize
     * @param string  $canonicalizationAlgorithm Canonicalization algorithm
     * @param array   $xpath                     XPATH
     * @param array   $nsPrefixes                Namespace prefixes
     *
     * @return string
     */
    private static function canonicalizeData(DOMNode $node, $canonicalizationAlgorithm, $xpath = null, $nsPrefixes = null)
    {
        $exclusive = false;
        $withComments = false;
        switch ($canonicalizationAlgorithm) {
            case self::C14N:
                $exclusive = false;
                $withComments = false;
                break;
            case self::C14N_COMMENTS:
                $exclusive = false;
                $withComments = true;
                break;
            case self::EXC_C14N:
                $exclusive = true;
                $withComments = false;
                break;
            case self::EXC_C14N_COMMENTS:
                $exclusive = true;
                $withComments = true;
                break;
            default:
                throw new InvalidArgumentException('canonicalizationAlgorithm', "Invalid canonicalization algorithm given: {$canonicalizationAlgorithm}");
        }

        return $node->C14N($exclusive, $withComments, $xpath, $nsPrefixes);
    }

    /**
     * Checks if mandatory parameters are given and throws Exception otherwise.
     *
     * @param array(string)         $mandatoryParameters List of mandatory parameters
     * @param string                $keyAlgorithm        Key algorithm
     * @param array(string=>string) $parameters          Parameter array that should be checked
     *
     * @return null
     * @throws MissingMandatoryParametersException
     */
    protected static function checkMandatoryParametersForPublicKeyCalculation(array $mandatoryParameters, $keyAlgorithm, $parameters)
    {
        foreach ($mandatoryParameters as $parameterName) {
            if (!isset($parameters[$parameterName])) {
                throw new MissingMandatoryParametersException("Can't create key from {$keyAlgorithm} key values. Missing parameter '{$parameterName}'");
            }
        }

        return null;
    }

    /**
     * Creates a new Signature node and appends it to the given node.
     *
     * @param Key        $keyForSignature           Key to sign
     * @param string     $canonicalizationAlgorithm Canonicalization algorithm
     * @param DOMNode    $appendTo                  Append signature node to this node
     * @param DOMNode    $insertBefore              Insert signature node before the given node
     * @param DOMElement $keyInfo                   KeyInfo element
     *
     * @return DOMElement
     */
    public static function createSignature(Key $keyForSignature, $canonicalizationAlgorithm, DOMNode $appendTo, DOMNode $insertBefore = null, DOMElement $keyInfo = null)
    {
        $doc = $appendTo->ownerDocument;
        $signature = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':Signature');

        if (!is_null($insertBefore)) {
            $appendTo->insertBefore($signature, $insertBefore);
        } else {
            $appendTo->appendChild($signature);
        }

        $signedInfo = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':SignedInfo');
        $signature->appendChild($signedInfo);

        $canonicalizationMethod = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', $canonicalizationAlgorithm);
        $signedInfo->appendChild($canonicalizationMethod);

        $signatureMethod = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', $keyForSignature->getAlgorithm());
        $signedInfo->appendChild($signatureMethod);

        if (!is_null($keyInfo)) {
            $signature->appendChild($keyInfo);
        }

        return $signature;
    }

    /**
     * Generate a pseudo-random version 4 UUID.
     *
     * @see http://de.php.net/manual/en/function.uniqid.php#94959
     *
     * @return string
     */
    public static function generateUUID()
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            // 16 bits for "time_mid"
            mt_rand(0, 0xffff),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000,
            // 48 bits for "node"
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    /**
     * Gets the security referenced in the given $signature element.
     *
     * You can add your own key resolver by calling:
     * $ns = 'myns';
     * $localname = 'MyKeyInfo';
     * $keyResolver = array('MyClass' => 'function');
     * \ass\XmlSecurity\DSig::addKeyInfoResolver($ns, $localName, $keyResolver);
     *
     * @param DOMElement $signature Signature element
     *
     * @return Key|null
     */
    public static function getSecurityKey(DOMElement $signature)
    {
        $encryptedMethod = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'SignatureMethod')->item(0);
        if (!is_null($encryptedMethod)) {
            $algorithm = $encryptedMethod->getAttribute('Algorithm');
            $keyInfo = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'KeyInfo')->item(0);
            if (!is_null($keyInfo)) {
                return self::getSecurityKeyFromKeyInfo($keyInfo, $algorithm);
            }
        }

        return null;
    }

    /**
     * Create a ds:KeyInfo with X509 certificate from given Key object
     *
     * @param DOMDocument $doc  DOMDocument to add the KeyInfo
     * @param Key         $cert Key containing certificate
     *
     * @return DOMElement
     */
    public static function createX509CertificateKeyInfo(DOMDocument $doc, Key $cert)
    {
        $publicCertificate = $cert->getX509Certificate(true);

        $keyInfo = $doc->createElementNS(DSig::NS_XMLDSIG, DSig::PFX_XMLDSIG.':KeyInfo');
        $x509Data = $doc->createElementNS(DSig::NS_XMLDSIG, DSig::PFX_XMLDSIG.':X509Data');
        $keyInfo->appendChild($x509Data);
        $x509Certificate = $doc->createElementNS(DSig::NS_XMLDSIG, DSig::PFX_XMLDSIG.':X509Certificate', $publicCertificate);
        $x509Data->appendChild($x509Certificate);

        return $keyInfo;
    }

    /**
     * Create a ds:KeyInfo with RSA key vlue from given Key object
     *
     * @param DOMDocument $doc DOMDocument to add the KeyInfo
     * @param Key         $key Key
     *
     * @return DOMElement
     */
    public static function createRSAKeyInfo(DOMDocument $doc, Key $key)
    {
        $keyDetails = $key->getDetails();

        if (OPENSSL_KEYTYPE_RSA != $keyDetails['type']) {
            throw InvalidArgumentException('key', 'Key type must be RSA.');
        }

        if (!isset($keyDetails['rsa']['n']) && !isset($keyDetails['rsa']['e'])) {
            throw InvalidArgumentException('key', 'RSA key details must contain modulus and public exponent.');
        }

        $keyInfo = $doc->createElementNS(DSig::NS_XMLDSIG, DSig::PFX_XMLDSIG.':KeyInfo');
        $rsaKeyValue = $doc->createElementNS(DSig::NS_XMLDSIG, DSig::PFX_XMLDSIG.':RSAKeyValue');
        $keyInfo->appendChild($rsaKeyValue);

        $modulusBase64 = base64_encode($keyDetails['rsa']['n']);
        $modulus = $doc->createElementNS(DSig::NS_XMLDSIG, DSig::PFX_XMLDSIG.':Modulus', $modulusBase64);
        $rsaKeyValue->appendChild($modulus);

        $exponentBase64 = base64_encode($keyDetails['rsa']['e']);
        $exponent = $doc->createElementNS(DSig::NS_XMLDSIG, DSig::PFX_XMLDSIG.':Exponent', $exponentBase64);
        $rsaKeyValue->appendChild($exponent);

        return $keyInfo;
    }

    /**
     * Gets the security key references within the given KeyInfo element.
     *
     * You can add your own key resolver by calling:
     * $ns = 'myns';
     * $localname = 'MyKeyInfo';
     * $keyResolver = array('MyClass' => 'function');
     * \ass\XmlSecurity\DSig::addKeyInfoResolver($ns, $localName, $keyResolver);
     *
     * @param DOMElement $keyInfo   KeyInfo element
     * @param string     $algorithm Key algorithm
     *
     * @return Key|null
     */
    public static function getSecurityKeyFromKeyInfo(DOMElement $keyInfo, $algorithm)
    {
        if (!is_null($keyInfo)) {
            foreach ($keyInfo->childNodes as $child) {
                if ($child instanceof DOMElement) {
                    $key = null;
                    if (isset(self::$keyInfoResolvers[$child->namespaceURI][$child->localName]) && is_callable(self::$keyInfoResolvers[$child->namespaceURI][$child->localName])) {
                        $key = call_user_func(self::$keyInfoResolvers[$child->namespaceURI][$child->localName], $child, $algorithm);
                    }
                    if (!is_null($key)) {
                        return $key;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Tries to resolve a key from the given DOMElement.
     *
     * @param DOMElement $node      KeyInfo element
     * @param string     $algorithm Key algorithm
     *
     * @return Key|null
     * @throws MissingMandatoryParametersException
     */
    private static function keyInfoKeyValueResolver(DOMElement $node, $algorithm)
    {
        foreach ($node->childNodes as $key) {
            if ($key->namespaceURI == self::NS_XMLDSIG) {
                switch ($key->localName) {
                    case 'DSAKeyValue':
                        $parameters = array();
                        foreach ($key->childNodes as $parameter) {
                            $parameters[$parameter->localName] = base64_decode($parameter->nodeValue);
                        }
                        $mandatoryParameters = array(
                            'P',
                            'Q',
                            'G',
                            'Y',
                        );
                        // throws exception if mandatory parameters check fails
                        self::checkMandatoryParametersForPublicKeyCalculation($mandatoryParameters, 'DSA', $parameters);
                        // calculate public key
                        $publicKey = Pem::getPublicKeyFromPqgy($parameters['P'], $parameters['Q'], $parameters['G'], $parameters['Y']);

                        return Key::factory($algorithm, $publicKey, Key::TYPE_PUBLIC);
                    case 'RSAKeyValue':
                        $parameters = array();
                        foreach ($key->childNodes as $parameter) {
                            $parameters[$parameter->localName] = base64_decode($parameter->nodeValue);
                        }
                        $mandatoryParameters = array(
                            'Modulus',
                            'Exponent',
                        );
                        // throws exception if mandatory parameters check fails
                        self::checkMandatoryParametersForPublicKeyCalculation($mandatoryParameters, 'DSA', $parameters);
                        // calculate public key
                        $publicKey = Pem::getPublicKeyFromModExp($parameters['Modulus'], $parameters['Exponent']);

                        return Key::factory($algorithm, $publicKey, Key::TYPE_PUBLIC);
                }
            }
        }

        return null;
    }

    /**
     * Tries to resolve a key from the given DOMElement.
     *
     * @param DOMElement $node      KeyInfo element
     * @param string     $algorithm Key algorithm
     *
     * @return Key|null
     */
    private static function keyInfoX509DataResolver(DOMElement $node, $algorithm)
    {
        $x509Certificate = $node->getElementsByTagNameNS(self::NS_XMLDSIG, 'X509Certificate')->item(0);
        if (!is_null($x509Certificate)) {
            $certificate = Pem::formatKeyInPemFormat($x509Certificate->textContent);

            return Key::factory($algorithm, $certificate, false, Key::TYPE_PUBLIC);
        }

        return null;
    }

    /**
     * Locates the 'ds:Signature' within the given DOMDocument or DOMNode.
     *
     * @param DOMNode $node Node within the signature should be located
     *
     * @return DOMElement
     */
    public static function locateSignature(DOMNode $node)
    {
        if ($node instanceof DOMDocument) {
            $doc = $node;
            $relativeTo = null;
        } else {
            $doc = $node->ownerDocument;
            $relativeTo = $node;
        }
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', self::NS_XMLDSIG);
        $query = './/ds:Signature';
        $nodes = $xpath->query($query, $relativeTo);
        if ($nodes->length > 0) {
            return $nodes->item(0);
        }

        return null;
    }

    /**
     * Process transformation.
     *
     * @param DOMNode              $node                    Not to transform
     * @param string               $transformationAlgorithm Transformation algorithm
     * @param array(string=>mixed) $options                 Options (xpath_transformation, inclusive_namespaces)
     *
     * @return string
     */
    private static function processTransform(DOMNode $node, $transformationAlgorithm, array $options = array())
    {
        switch ($transformationAlgorithm) {
            case self::XPATH:
                $xpath = null;
                if (isset($options['xpath_transformation'])) {
                    // http://xmlstar.sourceforge.net/doc/UG/ch04s06.html
                    $xpath = array(
                        'query' => '(.//. | .//@* | .//namespace::*)[' . $options['xpath_transformation']['query'] . ']',
                        'namespaces' => $options['xpath_transformation']['namespaces'],
                    );
                }

                return self::canonicalizeData($node, self::C14N, $xpath);
            case self::C14N:
            case self::C14N_COMMENTS:
                return self::canonicalizeData($node, $transformationAlgorithm);
            case self::EXC_C14N:
            case self::EXC_C14N_COMMENTS:
                $nsPrefixes = null;
                if (isset($options['inclusive_namespaces'])) {
                    $nsPrefixes = $options['inclusive_namespaces'];
                }

                return self::canonicalizeData($node, $transformationAlgorithm, null, $nsPrefixes);
            case self::TRANSFORMATION_ENVELOPED_SIGNATURE:
                // http://www.uberbrady.com/2008/10/horrifically-bad-technology.html
                $xpath = array(
                    'query' => sprintf('(//. | //@* | //namespace::*)[not(ancestor-or-self::%s:Signature)]', self::PFX_XMLDSIG),
                    'namespaces' => array(
                        self::PFX_XMLDSIG => self::NS_XMLDSIG
                    ),
                );

                return self::canonicalizeData($node, self::EXC_C14N, $xpath);
            default:
                throw new InvalidArgumentException('transformationAlgorithm', "Invalid transformation algorithm given: {$transformationAlgorithm}");
        }
    }

    /**
     * Sign the document.
     *
     * @param DOMElement $signature                 Signature element to sign
     * @param Key        $keyForSignature           Key used to sign data
     * @param string     $canonicalizationAlgorithm Canonicalization algorithm
     *
     * @return DOMElement
     */
    public static function signDocument(DOMElement $signature, Key $keyForSignature, $canonicalizationAlgorithm)
    {
        $doc = $signature->ownerDocument;
        $signedInfo = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'SignedInfo')->item(0);
        if (!is_null($signedInfo)) {
            $canonicalizedData = self::canonicalizeData($signedInfo, $canonicalizationAlgorithm);
            $signatureValueString = base64_encode($keyForSignature->signData($canonicalizedData));
            $signatureValue = $doc->createElementNS(self::NS_XMLDSIG, self::PFX_XMLDSIG . ':SignatureValue', $signatureValueString);
            $keyInfo = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'KeyInfo')->item(0);
            $signature->insertBefore($signatureValue, $keyInfo);
        }

        return $signatureValue;
    }

    /**
     * Verify the document's signature.
     *
     * @param DOMElement $signature       Signature element to verify
     * @param Key        $keyForSignature Key to validate signature
     *
     * @return boolean
     */
    public static function verifyDocumentSignature(DOMElement $signature, Key $keyForSignature = null)
    {
        if (is_null($keyForSignature)) {
            $keyForSignature = self::getSecurityKey($signature);
        }

        $signedInfo = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'SignedInfo')->item(0);
        if (!is_null($signedInfo)) {
            $canonicalizationMethod = $signedInfo->getElementsByTagNameNS(self::NS_XMLDSIG, 'CanonicalizationMethod')->item(0);
            if (!is_null($canonicalizationMethod)) {
                $canonicalizationAlgorithm = $canonicalizationMethod->getAttribute('Algorithm');
                $signatureValue = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'SignatureValue')->item(0);
                if (!is_null($signatureValue)) {
                    $canonicalizedData = self::canonicalizeData($signedInfo, $canonicalizationAlgorithm);
                    $decodedSignatureValueFromSoapMessage = base64_decode($signatureValue->textContent);

                    return $keyForSignature->verifySignature($canonicalizedData, $decodedSignatureValueFromSoapMessage);
                }
            }
        }

        return false;
    }

    /**
     * Get list of reference nodes.
     *
     * @param DOMElement $signature Signature element
     * @param array      $options   Options (xpath_transformation, inclusive_namespaces)
     *
     * @return array(DOMElement)
     */
    public static function getReferenceNodes(DOMElement $signature, array $options = array())
    {
        if ($signature instanceof DOMDocument) {
            $doc = $signature;
        } else {
            $doc = $signature->ownerDocument;
        }
        $xpath = new DOMXPath($doc);

        $idName = 'Id';
        if (isset($options['id_name'])) {
            $idName = $options['id_name'];
        }
        $idNamespace = null;
        if (isset($options['id_ns_prefix']) && isset($options['id_prefix_ns'])) {
            $idName = $options['id_ns_prefix'] . ':' . $idName;
            $idNamespace = $options['id_prefix_ns'];
            $xpath->registerNamespace($options['id_ns_prefix'], $options['id_prefix_ns']);
        }

        $referenceNodes = array();

        $signedInfo = $signature->getElementsByTagNameNS(self::NS_XMLDSIG, 'SignedInfo')->item(0);
        if (!is_null($signedInfo)) {
            $nodes = $signedInfo->getElementsByTagNameNS(self::NS_XMLDSIG, 'Reference');
            if ($nodes->length > 0) {
                foreach ($nodes as $reference) {
                    $uri = $reference->getAttribute('URI');
                    if ($uri !== null && $uri !== '') {
                        $url = parse_url($uri);
                        $referenceId = $url['fragment'];
                        // get referenced node
                        if (!is_null($idNamespace)) {
                            $query = '//*[@' . $idName . '="' . $referenceId . '" or @Id="' . $referenceId . '"]';
                        } else {
                            $query = '//*[@' . $idName . '="' . $referenceId . '"]';
                        }
                        $node = $xpath->query($query)->item(0);
                    } else {
                        $node = $doc;
                    }

                    $referenceNodes[] = array(
                        'ref'  => $reference,
                        'node' => $node,
                    );
                }
            }
        }

        return $referenceNodes;
    }

    /**
     * Verify the given node.
     *
     * @param DOMElement $reference Reference node element to be verified
     * @param DOMNode    $node      Node element to be verified
     *
     * @return boolean
     */
    private static function verifyReference(DOMElement $reference, DOMNode $node)
    {
        $isValid = false;

        // get tranformation method and canonicalize data
        $transform = $reference->getElementsByTagNameNS(self::NS_XMLDSIG, 'Transform')->item(0);
        if (!is_null($transform)) {
            $transformationAlgorithm = $transform->getAttribute('Algorithm');
            $options = array();

            switch ($transformationAlgorithm) {
                case self::XPATH:
                    $xpathNode = $transform->getElementsByTagNameNS(self::NS_XMLDSIG, 'XPath')->item(0);
                    if (!is_null($xpathNode)) {
                        $options['xpath_transformation']['query'] = $xpathNode->nodeValue;
                        $options['xpath_transformation']['namespaces'] = array();
                        $xpath = new DOMXPath($reference->ownerDocument);
                        $nslist = $xpath->query('./namespace::*', $xpathNode);
                        foreach ($nslist as $nsnode) {
                            if ($nsnode->localName != 'xml') {
                                $options['xpath_transformation']['namespaces'][$nsnode->localName] = $nsnode->nodeValue;
                            }
                        }
                    }
                    break;
                case self::EXC_C14N:
                    $inclusiveNamespaces = $transform->getElementsByTagNameNS(self::EXC_C14N, 'InclusiveNamespaces')->item(0);
                    if (!is_null($inclusiveNamespaces)) {
                        $prefixList = $transform->getAttribute('PrefixList');
                        $nsPrefixes = explode(' ', $prefixList);
                        if (count($nsPrefixes) > 0) {
                            $options['inclusive_namespaces'] = $nsPrefixes;
                        }
                    }
                    break;
            }

            $transformedData = self::processTransform($node, $transformationAlgorithm, $options);
            $digestMethod = $reference->getElementsByTagNameNS(self::NS_XMLDSIG, 'DigestMethod')->item(0);
            if (!is_null($digestMethod)) {
                $digestAlgorithm = $digestMethod->getAttribute('Algorithm');
                $digestValueString = self::calculateDigest($transformedData, $digestAlgorithm);
                $digestValue = $reference->getElementsByTagNameNS(self::NS_XMLDSIG, 'DigestValue')->item(0);
                if (!is_null($digestValue)) {
                    if ($digestValueString == $digestValue->textContent) {
                        $isValid = true;
                    }
                }
            }
        }

        return $isValid;
    }

    /**
     * Verify the document's signature.
     *
     * @param DOMElement $signature Signature element
     * @param array      $options   Options (xpath_transformation, inclusive_namespaces)
     *
     * @return boolean
     */
    public static function verifyReferences(DOMElement $signature, array $options = array())
    {
        $referenceNodes = self::getReferenceNodes($signature, $options);
        if (count($referenceNodes) > 0) {
            $allValid = true;
            foreach ($referenceNodes as $referenceNode) {
                $isValid = self::verifyReference($referenceNode['ref'], $referenceNode['node']);
                $allValid = ($allValid === false) ? false : $isValid;
            }

            return $allValid;
        }

        return false;
    }

}
