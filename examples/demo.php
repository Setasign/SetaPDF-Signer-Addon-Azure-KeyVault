<?php

use GuzzleHttp\Client as GuzzleClient;
use Mjelamanov\GuzzlePsr18\Client;
use Http\Factory\Guzzle\RequestFactory;
use Http\Factory\Guzzle\StreamFactory;
use setasign\SetaPDF\Signer\Module\AzureKeyVault\Module as AzureKeyVaultModule;

require_once __DIR__ . '/../vendor/autoload.php';

$settings = require 'settings.php';
$tenantId = $settings['tenantId'];
$appClientId = $settings['appClientId'];
$appClientSecret = $settings['appClientSecret'];
$vaultBaseUrl = $settings['vaultBaseUrl'];
$certificateName = $settings['certificateName'];
$certificateVersion = $settings['certificateVersion'];
$digest = isset($settings['digest']) ? $settings['digest'] : null;
$alg = isset($settings['alg']) ? $settings['alg'] : null;

$httpClient = new Client(new GuzzleClient([
    'http_errors' => false,
    //'verify' => './cert.pem'
]));
$azureModule = new AzureKeyVaultModule(
    $vaultBaseUrl,
    $certificateName,
    $certificateVersion,
    $httpClient,
    new RequestFactory(),
    new StreamFactory()
);

if (file_exists(__DIR__ . '/token')) {
    $token = unserialize(file_get_contents(__DIR__ . '/token'), ['allowed_classes' => false]);
}
if (!isset($token, $token['accessToken'], $token['expires']) || $token['expires'] < (time() - 60)) {
    $token = $azureModule->createTokenBySharedSecret($tenantId, $appClientId, $appClientSecret);
    file_put_contents(__DIR__ . '/token', serialize($token));
}
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
