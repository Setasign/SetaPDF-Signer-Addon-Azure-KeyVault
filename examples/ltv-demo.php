<?php
/* This example uses a certificate from https://www.ensured.com/automated-signing which
 * private key is stored in Azure Key Vault on an HSM (sorry, you cannot execute it
 * without getting your own certificate and key).
 *
 * It also uses a timestamp and additionally adds revocation information to both the CMS
 * container and appends a complete VRI package at the end in a document security store.
 */

declare(strict_types=1);

use GuzzleHttp\Client as GuzzleClient;
use Mjelamanov\GuzzlePsr18\Client as Psr18Wrapper;
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

$certificatePath = __DIR__ . '/assets/setapdf_demos@setasign_com.crt';
$trustedCertificatesPath = __DIR__ . '/assets/setapdf_demos@setasign_com.ca-bundle';

$timestampingUrl = 'http://timestamping.ensuredca.com';

$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$guzzleOptions = ['http_errors' => false];
if (file_exists(__DIR__ . '/cacert.pem')) {
    $guzzleOptions['verify'] = __DIR__ . '/cacert.pem';
}

$httpClient = new GuzzleClient($guzzleOptions);
// only required if you are using guzzle < 7
$httpClient = new Psr18Wrapper($httpClient);

$azureModule = new AzureKeyVaultModule(
    $vaultBaseUrl,
    $certificateName,
    $certificateVersion,
    $httpClient,
    new RequestFactory(),
    new StreamFactory()
);

// a new access token will be generated for every run
$token = $azureModule->createTokenBySharedSecret($tenantId, $appClientId, $appClientSecret);
// alternativly you can remember you last access token
// this is a simple example using the file system. redis or memcache may be a better solution
//if (file_exists(__DIR__ . '/token')) {
//    $token = json_decode(file_get_contents(__DIR__ . '/token'), true);
//}
//if (!isset($token, $token['accessToken'], $token['expires']) || $token['expires'] < (time() - 60)) {
//    $token = $azureModule->createTokenBySharedSecret($tenantId, $appClientId, $appClientSecret);
//    file_put_contents(__DIR__ . '/token', json_encode($token, JSON_PRETTY_PRINT));
//}
$azureModule->setAccessToken($token['accessToken']);

// we use a local copy of the certificate
$certificate = SetaPDF_Signer_X509_Certificate::fromFile($certificatePath);
$azureModule->setCertificate($certificate);

// create a collection of trusted certificats:
$trustedCertificates = new SetaPDF_Signer_X509_Collection(
    SetaPDF_Signer_Pem::extractFromFile($trustedCertificatesPath)
);

// create a collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);
// collect revocation information for this certificate
$vriData = $collector->getByCertificate($certificate);

// now add these information to the CMS container
$azureModule->setExtraCertificates($vriData->getCertificates());
foreach ($vriData->getOcspResponses() as $ocspResponse) {
    $azureModule->addOcspResponse($ocspResponse);
}
foreach ($vriData->getCrls() as $crl) {
    $azureModule->addCrl($crl);
}

// create a writer instance
$writer = new SetaPDF_Core_Writer_File($resultPath);
$tmpWriter = new SetaPDF_Core_Writer_TempFile();
// create the document instance
$document = SetaPDF_Core_Document::loadByFilename($fileToSign, $tmpWriter);

// create the signer instance
$signer = new SetaPDF_Signer($document);
// because of the timestamp and VRI data we need more space for the signature container
$signer->setSignatureContentLength(25500);
if ($digest !== null) {
    $azureModule->setDigest($digest);
}
if ($alg !== null) {
    $azureModule->setSignatureAlgorithm($alg);
}

// setup a timestamp module
$tsModule = new SetaPDF_Signer_Timestamp_Module_Rfc3161_Curl($timestampingUrl);
$signer->setTimestampModule($tsModule);

// add a signature field manually to get access to its name
$signatureField = $signer->addSignatureField();
// ...this is needed to add validation related information later
$signer->setSignatureFieldName($signatureField->getQualifiedName());

// sign the document with the private key in Azure
$signer->sign($azureModule);

// create a new instance
$document = SetaPDF_Core_Document::loadByFilename($tmpWriter->getPath(), $writer);

// create a VRI collector instance
$collector = new SetaPDF_Signer_ValidationRelatedInfo_Collector($trustedCertificates);
// Use IPv4 to bypass an issue at http://ocsp.ensuredca.com
//$collector->getOcspClient()->setCurlOption([
//    CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4
//]);

// get VRI for the timestamp signature
$vriData = $collector->getByFieldName(
    $document,
    $signatureField->getQualifiedName(),
    SetaPDF_Signer_ValidationRelatedInfo_Collector::SOURCE_OCSP_OR_CRL,
    null,
    null,
    $vriData // pass the previously gathered VRI data
);

//$logger = $collector->getLogger();
//foreach ($logger->getLogs() as $log) {
//    echo str_repeat(' ', $log->getDepth() * 4) . $log . "\n";
//}

// and add it to the document.
$dss = new SetaPDF_Signer_DocumentSecurityStore($document);
$dss->addValidationRelatedInfoByFieldName(
    $signatureField->getQualifiedName(),
    $vriData->getCrls(),
    $vriData->getOcspResponses(),
    $vriData->getCertificates()
);

// save and finish the final document
$document->save()->finish();