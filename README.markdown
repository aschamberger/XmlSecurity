The XmlSecurity library is written in PHP for working with XML Encryption and
Signatures.

Installation:
=============
You can install the library with [`composer.phar`][1]. Create a `composer.json` file:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "git@github.com:aschamberger/XmlSecurity.git"
        }
    ],
    "require": {
        "ass/xmlsecurity": "dev-master"
    }
}
```
Now you are ready to install the library:

```sh
$ curl -s https://getcomposer.org/installer | php && php composer.phar install
```

Origin:
=======

Large portions of the library are derived from the [xmlseclibs PHP library for
XML Security][2]. Copyright (c) 2007-2010, Robert Richards
<rrichards@cdatazone.org>. All rights reserved.

[1]: http://getcomposer.org
[2]: http://code.google.com/p/xmlseclibs/
