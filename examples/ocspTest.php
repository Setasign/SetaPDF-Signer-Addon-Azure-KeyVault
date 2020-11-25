<?php

require_once __DIR__ . '/../vendor/autoload.php';

$bundle = new SetaPDF_Signer_X509_Collection(
    SetaPDF_Signer_Pem::extractFromFile(__DIR__ . '/assets/setapdf_demos@setasign_com.ca-bundle')
);
$certificate = SetaPDF_Signer_X509_Certificate::fromFile(__DIR__ . '/assets/setapdf_demos@setasign_com.crt');
$issuer = $certificate->getIssuer($bundle);

$request = new SetaPDF_Signer_Ocsp_Request();
$request->add($certificate, $issuer);

$s = microtime(true);
$ocspClient = new SetaPDF_Signer_Ocsp_Client('http://ocsp.ensuredca.com');
$ocspClient->setCurlOption([
    CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4
]);
$response = $ocspClient->send($request);

echo (microtime(true) - $s);