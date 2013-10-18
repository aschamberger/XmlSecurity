<?php

namespace ass\XmlSecurity\Tests;

use ass\XmlSecurity\Pem;

class PemTest extends \PHPUnit_Framework_TestCase
{
    protected $fixturesDir;
    protected $cert;
    protected $pubKey;
    protected $keyString;

    protected function setUp()
    {
        $this->fixturesDir = __DIR__ . "/Fixtures";
        $this->cert = file_get_contents($this->fixturesDir.'/mycert.pem');
        $this->pubKey = file_get_contents($this->fixturesDir.'/pubkey.pem');
        $this->keyString = 'MIIEVDCCAzygAwIBAgIJAPTrkMJbCOr1MA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVNYWluZTESMBAGA1UEBxMJTGltaW5ndG9uMR8wHQYDVQQKExZ4bWxzZWNsaWJzLnBocCBMaWJyYXJ5MSUwIwYDVQQDExx4bWxzZWNsaWJzL3d3dy5jZGF0YXpvbmUub3JnMB4XDTA4MDcwNzIwMjIzMVoXDTE4MDcwNTIwMjIzMVoweTELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBU1haW5lMRIwEAYDVQQHEwlMaW1pbmd0b24xHzAdBgNVBAoTFnhtbHNlY2xpYnMucGhwIExpYnJhcnkxJTAjBgNVBAMTHHhtbHNlY2xpYnMvd3d3LmNkYXRhem9uZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDttdMyM5ISVD1Uz+BHAPrxVJ6N1eZonfg3DMvZVT0Zy64+qcXj8zuHC6lolDsfGnD8LUttraQ7qCL+bHKps+hjAhCRdx5Wcn4iDrlFpxFL7INnr6vekzsCQ45BPUrvksF9FKa7yX4iSDButmPfoT14gPnIuSe8Y5UeGe6Lk6sF0WgHyL+JmxOu377Kuhah2pXZ1+z7V4JIlNgemJtKlqrvgGeuE9TagfGHUL9BuZK5fUx/RSDUjqxUeKU3fft9fGIAZl0dduitC2Otv4dr1gxLrUmI+ZZ75FmtfKQT7SmS92QVI2B5WAPlL1bnbvhkZiyw7nFE+Q/wGJ2myE4RIFjdAgMBAAGjgd4wgdswHQYDVR0OBBYEFEC5iG0uGXLpQG/zMj/4TuDWfTpHMIGrBgNVHSMEgaMwgaCAFEC5iG0uGXLpQG/zMj/4TuDWfTpHoX2kezB5MQswCQYDVQQGEwJVUzEOMAwGA1UECBMFTWFpbmUxEjAQBgNVBAcTCUxpbWluZ3RvbjEfMB0GA1UEChMWeG1sc2VjbGlicy5waHAgTGlicmFyeTElMCMGA1UEAxMceG1sc2VjbGlicy93d3cuY2RhdGF6b25lLm9yZ4IJAPTrkMJbCOr1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBACmSKrte07VrGB8dtrN5mrt28ILickQjguu46h6vChgQ4YfIAoA1KWNsZJUuuIzTDjE5xz2hsW37CI0yrNesv2ho2hhP+fIaxCGmcwLYXL80UaPRglYk5+wPWFOt3QFAVoEgwjLX9+y+c2Gu7xLgHAFZVRjQ5hhKT0Nj3vhnt0k8LcognNl1wKuWda7VL4tODp/2IOXr5o5v/OL3UesGfeWfvr8LVmMc5f7/vLAu1+2Yk+/C9/EZyf3BDZQ4z8ae/iwqprCTUIEjhUDcq4+0YN2EIw6suGE2FtWlsIywNErmoOhdrmntU61n3nFCQBi7QDUnZrAFrl4/bmk3eRJ00nE=';
    }

    public function testFormatKeyInPemFormat()
    {
        $cert = Pem::formatKeyInPemFormat($this->keyString, PEM::PEM_TYPE_CERTIFICATE_X509);

        $this->assertEquals($cert, $this->cert);
    }

    public function testGetPublicKeyFromModExp()
    {
        $modulus = 'edb5d332339212543d54cfe04700faf1549e8dd5e6689df8370ccbd9553d19cbae3ea9c5e3f33b870ba968943b1f1a70fc2d4b6dada43ba822fe6c72a9b3e863021091771e56727e220eb945a7114bec8367afabde933b02438e413d4aef92c17d14a6bbc97e2248306eb663dfa13d7880f9c8b927bc63951e19ee8b93ab05d16807c8bf899b13aedfbecaba16a1da95d9d7ecfb57824894d81e989b4a96aaef8067ae13d4da81f18750bf41b992b97d4c7f4520d48eac5478a5377dfb7d7c6200665d1d76e8ad0b63adbf876bd60c4bad4988f9967be459ad7ca413ed2992f764152360795803e52f56e76ef864662cb0ee7144f90ff0189da6c84e112058dd';
        $binModulus = pack('H*', $modulus);
        $exponent = '010001'; // 65537 (0x10001)
        $binExponent = pack('H*', $exponent);
        $pubKey = Pem::getPublicKeyFromModExp($binModulus, $binExponent);

        $this->assertEquals($pubKey, $this->pubKey);
    }

    public function testParseKeyFromPemFormat()
    {
        $keys = Pem::parseKeyFromPemFormat($this->cert, PEM::PEM_TYPE_CERTIFICATE_X509);
        $keyString = array_pop($keys);

        $this->assertEquals($keyString, $this->keyString);
    }
}