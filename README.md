#  SetaPDF-Signer component modules for the Azure Key Vault service.

This package offers modules for the [SetaPDF-Signer](https://www.setasign.com/signer) component that allow you to use
the [Azure Key Vault service](https://azure.microsoft.com/services/key-vault/) by 
[Microsoft](https://www.microsoft.com) to **digital sign PDF documents in pure PHP**.

## Requirements

To use this package you need credentials for the Azure Key Vault Service.

This package is developed and tested on PHP >= 7.0. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

We're using [PSR-17 (HTTP Factories)](https://www.php-fig.org/psr/psr-17/) and [PSR-18 (HTTP Client)](https://www.php-fig.org/psr/psr-18/)
for the requests. So you'll need an implementation of these. We recommend using Guzzle. 

### For PHP 7.0 and 7.1
```
    "require" : {
        "guzzlehttp/guzzle": "^6.5",
        "http-interop/http-factory-guzzle": "^1.0",
        "mjelamanov/psr18-guzzle": "^1.3"
    }
```

### For >= PHP 7.2
```
    "require" : {
        "guzzlehttp/guzzle": "^7.0",
        "http-interop/http-factory-guzzle": "^1.0"
    }
```

## Installation
Add following to your composer.json:

```json
{
    "require": {
        "setasign/seta-pdf-signer-addon-azure-keyvault": "^1.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

### Evaluation version
By default this packages depends on a licensed version of the [SetaPDF-Signer](https://www.setasign.com/signer)
component. If you want to use it with an evaluation version please use following in your composer.json:

```json
{
    "require": {
        "setasign/seta-pdf-signer-addon-azure-keyvault": "dev-evaluation"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

### Without Composer

Make sure, that the [SetaPDF-Signer](https://www.setasign.com/signer) component 
is [installed](https://manuals.setasign.com/setapdf-core-manual/installation/#index-2) and
its [autoloader is registered](https://manuals.setasign.com/setapdf-core-manual/getting-started/#index-1) correctly.

Then simply require the `src/autoload.php` file or register this package in your own PSR-4 compatible autoload implementation:

```php
$loader = new \Example\Psr4AutoloaderClass;
$loader->register();
$loader->addNamespace('setasign\SetaPDF\Signer\Module\AzureKeyVault', 'path/to/src/');
```

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\AzureKeyVault`.

### The `Module` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer)
component. Its constructor requires 6 arguments:

`$vaultBaseUrl` The base url of your key vault.
`$certificateName` The name of your key.
`$certificateVersion` The version of your key.
`$httpClient` PSR-18 HTTP Client implementation.
`$requestFactory` PSR-17 HTTP Factory implementation.
`$streamFactory` PSR-17 HTTP Factory implementation.
A simple complete signature process would look like this:

```php
$httpClient = new Mjelamanov\GuzzlePsr18\Client(new GuzzleHttp\Client([
    'http_errors' => false,
    //'verify' => './cert.pem'
]));
$azureModule = new setasign\SetaPDF\Signer\Module\AzureKeyVault\Module(
    $vaultBaseUrl,
    $certificateName,
    $certificateVersion,
    $httpClient,
    new Http\Factory\Guzzle\RequestFactory(),
    new Http\Factory\Guzzle\StreamFactory()
);

$token = $azureModule->createTokenBySharedSecret($tenantId, $appClientId, $appClientSecret);
$azureModule->setAccessToken($token['accessToken']);

// the file to sign
$fileToSign = __DIR__ . '/Laboratory-Report.pdf';

// create a writer instance
$writer = new SetaPDF_Core_Writer_File('signed.pdf');
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new SetaPDF_Signer($document);
if ($digest !== null) {
    $azureModule->setDigest($digest);
}
if ($alg !== null) {
    $azureModule->setSignatureAlgorithm($alg);
}
$signer->sign($azureModule);
```

## License

This package is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).