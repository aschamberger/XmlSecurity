<?php

namespace ass\XmlSecurity\Tests;

use ass\XmlSecurity\Key\TripleDesCbc;

use ass\XmlSecurity\Key;

class KeyTest extends \PHPUnit_Framework_TestCase
{
    protected $fixturesDir;

    protected function setUp()
    {
        $this->fixturesDir = __DIR__ . "/Fixtures";
    }

    public function testThumbprint()
    {
        $key = Key::factory(Key::RSA_OAEP_MGF1P, $this->fixturesDir.'/mycert.pem', true, Key::TYPE_PUBLIC);
        $thumbprint = $key->getX509Thumbprint();

        $this->assertEquals("8b600d9155e8e8dfa3c10998f736be086e83ef3b", $thumbprint, "Certificate thumbprint check");
    }

    public function testGenerateSessionKeySize()
    {
        $keysizes = array(
            Key::TRIPLEDES_CBC => 24,
            Key::AES128_CBC => 16,
            Key::AES192_CBC => 24,
            Key::AES256_CBC => 32,
        );

        foreach ($keysizes as $type => $keysize) {
            $key = Key::factory($type);

            $this->assertEquals($keysize, strlen($key->getKey()), "Check that generated keys have the correct Keysize");
        }
    }

    public function testGenerateSessionKeyParity()
    {
        /* Run the test several times, to increase the chance of detecting an error. */
        for ($t = 0; $t < 16; $t++) {
            $key = Key::factory(Key::TRIPLEDES_CBC);
            $k = $key->getKey();

            for ($i = 0; $i < strlen($k); $i++) {
                $byte = ord($k[$i]);
                $parity = 0;
                while ($byte !== 0) {
                    $parity ^= $byte & 1;
                    $byte >>= 1;
                }

                $this->assertEquals(1, $parity, "Check that generated triple-des keys have the correct parity.");
            }
        }
    }

    public function testTripleDesAxisDecryption()
    {
        $files = array(
            'cipher_one.txt' => 'key_one.txt',
            'cipher_two.txt' => 'key_two.txt',
        );
        $expected = file_get_contents($this->fixturesDir.'/Key/result.txt');

        foreach ($files as $cipher => $key) {
            $key = file_get_contents($this->fixturesDir.'/Key/'.$key);
            $tripleDes = new TripleDesCbc($key);
            $data = file_get_contents($this->fixturesDir.'/Key/'.$cipher);
            $result = $tripleDes->decryptData($data);

            $this->assertEquals($expected, $result, "Check that 3des cbc encrypted cipher is properly decrypted.");

        }
    }
}