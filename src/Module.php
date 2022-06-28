<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\AzureKeyVault;

use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SetaPDF_Core_Document as Document;
use SetaPDF_Core_Reader_FilePath as FilePath;
use SetaPDF_Core_Type_Dictionary as Dictionary;
use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Asn1_Oid as Asn1Oid;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Exception;
use SetaPDF_Signer_Signature_DictionaryInterface;
use SetaPDF_Signer_Signature_DocumentInterface;
use SetaPDF_Signer_Signature_Module_ModuleInterface;
use SetaPDF_Signer_Signature_Module_Pades;
use SetaPDF_Signer_X509_Certificate;

/**
 * The signature module for the SetaPDF-Signer component
 */
class Module implements
    SetaPDF_Signer_Signature_Module_ModuleInterface,
    SetaPDF_Signer_Signature_DictionaryInterface,
    SetaPDF_Signer_Signature_DocumentInterface
{
    /**
     * @var string The base url of your key vault.
     */
    protected $vaultBaseUrl;

    /**
     * @var string The name of your key.
     */
    protected $certificateName;

    /**
     * @var string The version of your key.
     */
    protected $certificateVersion;

    /**
     * @var ClientInterface PSR-18 HTTP Client implementation.
     */
    protected $httpClient;

    /**
     * @var RequestFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $requestFactory;

    /**
     * @var StreamFactoryInterface PSR-17 HTTP Factory implementation.
     */
    protected $streamFactory;

    /**
     * @var SetaPDF_Signer_Signature_Module_Pades Internal pades module.
     */
    protected $padesModule;

    /**
     * @var null|string Active access token.
     */
    protected $accessToken;

    /**
     * @var null|string Forced signature algorithm.
     */
    protected $signatureAlgorithm;

    /**
     * Module constructor.
     *
     * @param string $vaultBaseUrl The base url of your key vault.
     * @param string $certificateName The name of your key.
     * @param string $certificateVersion The version of your key.
     * @param ClientInterface $httpClient PSR-18 HTTP Client implementation.
     * @param RequestFactoryInterface $requestFactory PSR-17 HTTP Factory implementation.
     * @param StreamFactoryInterface $streamFactory PSR-17 HTTP Factory implementation.
     */
    public function __construct(
        string $vaultBaseUrl,
        string $certificateName,
        string $certificateVersion,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->vaultBaseUrl = (string) $vaultBaseUrl;
        $this->certificateName = (string) $certificateName;
        $this->certificateVersion = (string) $certificateVersion;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->padesModule = new SetaPDF_Signer_Signature_Module_Pades();
    }

    /**
     * Set the digest algorithm to use when signing.
     *
     * @param string $digest Allowed values are sha256, sha386, sha512
     * @see SetaPDF_Signer_Signature_Module_Pades::setDigest()
     */
    public function setDigest(string $digest)
    {
        $this->padesModule->setDigest($digest);
    }

    /**
     * Get the digest algorithm.
     *
     * @return string
     */
    public function getDigest(): string
    {
        return $this->padesModule->getDigest();
    }

    /**
     * Enforce the used signature algorithm.
     *
     * @param string $algorithm See azure documentation for the available options.
     * @see https://docs.microsoft.com/de-de/rest/api/keyvault/sign/sign
     */
    public function setSignatureAlgorithm(string $algorithm)
    {
        $this->signatureAlgorithm = $algorithm;
    }

    /**
     * Get the forced signature algorithm.
     *
     * @return string|null
     */
    public function getSignatureAlgorithm()
    {
        return $this->signatureAlgorithm;
    }

    /**
     * Search for the matching signature algorithm in the used certificate.
     *
     * Note: if the certificate isn't set yet it will be fetched first.
     *
     * @return string
     * @throws SetaPDF_Signer_Exception
     */
    public function findSignatureAlgorithm(): string
    {
        $certificate = $this->getCertificate();
        if (!$certificate instanceof SetaPDF_Signer_X509_Certificate) {
            $certificate = SetaPDF_Signer_X509_Certificate::fromFileOrString($certificate);
        }

        $signAlgorithmOid = $certificate->getSubjectPublicKeyInfoAlgorithmIdentifier()[0];
        if (!isset(Digest::$algorithmOids[$signAlgorithmOid])) {
            throw new Exception(\sprintf('Unknown algorithm "%s".', $signAlgorithmOid));
        }

        $signAlgorithm = Digest::$algorithmOids[$signAlgorithmOid];
        $padesDigest = $this->padesModule->getDigest();

        switch ($signAlgorithm) {
            case Digest::RSA_PSS_ALGORITHM:
                switch ($padesDigest) {
                    case Digest::SHA_256:
                        return 'PS256';
                    case Digest::SHA_384:
                        return 'PS384';
                    case Digest::SHA_512:
                        return 'PS512';
                }
                throw new Exception(\sprintf('Unknown pades digest "%s".', $padesDigest));

            case Digest::RSA_ALGORITHM:
                switch ($padesDigest) {
                    case Digest::SHA_256:
                        return 'RS256';
                    case Digest::SHA_384:
                        return 'RS384';
                    case Digest::SHA_512:
                        return 'RS512';
                }
                throw new Exception(\sprintf('Unknown pades digest "%s".', $padesDigest));

            case Digest::ECDSA_ALGORITHM:
                switch ($padesDigest) {
                    case Digest::SHA_256:
                        return 'ES256';
                    case Digest::SHA_384:
                        return 'ES384';
                    case Digest::SHA_512:
                        return 'ES512';
                }
                throw new Exception(\sprintf('Unknown pades digest "%s".', $padesDigest));
        }
        throw new Exception(\sprintf('Unknown sign algorithm "%s".', $signAlgorithm));
    }

    /**
     * @param string $data
     * @return false|string
     * @see https://tools.ietf.org/html/rfc4648#section-5
     */
    protected function base64url_decode(string $data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * @param string $data
     * @return string
     * @see https://tools.ietf.org/html/rfc4648#section-5
     */
    protected function base64url_encode(string $data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * json_decode wrapper to handle invalid json. Can be removed with php7.3 and JSON_THROW_ON_ERROR
     *
     * @param string $json The json string being decoded. This function only works with UTF-8 encoded strings.
     * @param bool $assoc When TRUE, returned objects will be converted into associative arrays.
     * @param int $depth
     * @param int $options
     * @return mixed
     */
    protected function json_decode(string $json, bool $assoc = false, int $depth = 512, int $options = 0)
    {
        // Clear json_last_error()
        \json_encode(null);

        $data = @\json_decode($json, $assoc, $depth, $options);

        if (\json_last_error() !== JSON_ERROR_NONE) {
            throw new InvalidArgumentException(\sprintf(
                'Unable to decode JSON: %s',
                \json_last_error_msg()
            ));
        }
        return $data;
    }

    /**
     * Create an access token by a shared secret.
     *
     * @param string $tenant The directory tenant the application plans to operate against, in GUID or domain-name
     *                       format.
     * @param string $appClientId The application ID that's assigned to your app. You can find this information in the
     *                            portal where you registered your app.
     * @param string $appClientSecret The client secret that you generated for your app in the app registration portal.
     *                                The client secret must be URL-encoded before being sent.
     * @param string $scope The value passed for the scope parameter in this request should be the resource identifier
     *                      (application ID URI) of the resource you want, affixed with the .default suffix. For the
     *                      Microsoft Graph example, the value is https://graph.microsoft.com/.default. This value
     *                      tells the Microsoft identity platform endpoint that of all the direct application
     *                      permissions you have configured for your app, the endpoint should issue a token for the
     *                      ones associated with the resource you want to use. To learn more about the /.default scope,
     *                      see the consent documentation.
     * @return array{accessToken: string, expires: int Timestamp}
     * @throws Exception
     * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#first-case-access-token-request-with-a-shared-secret
     */
    public function createTokenBySharedSecret(
        string $tenant,
        string $appClientId,
        string $appClientSecret,
        string $scope = 'https://vault.azure.net/.default'
    ): array {
        try {
            $response = $this->httpClient->sendRequest(
                $this->requestFactory->createRequest(
                    'POST',
                    'https://login.microsoftonline.com/' . $tenant . '/oauth2/v2.0/token'
                )
                ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
                ->withBody($this->streamFactory->createStream(http_build_query([
                    'scope' => $scope,
                    'grant_type' => 'client_credentials',
                    'client_id' => $appClientId,
                    'client_secret' => $appClientSecret
                ])))
            );
        } catch (ClientExceptionInterface $e) {
            throw new Exception('Connection error!', 0, $e);
        }
        $responseBody = (string) $response->getBody();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        $token = $this->json_decode($responseBody, true);
        if ($token['token_type'] !== 'Bearer') {
            throw new Exception(\sprintf('Unexpected token type returned "%s".', $token['token_type']));
        }

        return [
            'accessToken' => $token['access_token'],
            'expires' => time() + $token['expires_in']
        ];
    }

    /**
     * Sets the access token to authenticate to the web API.
     *
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Fetch the certificate from azure key vault.
     *
     * You can use this to cache the certificate locally.
     *
     * @return SetaPDF_Signer_X509_Certificate The certificate from the azure key vault.
     * @throws Exception
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @see https://docs.microsoft.com/de-de/rest/api/keyvault/getcertificate/getcertificate
     */
    public function fetchCertificate(): SetaPDF_Signer_X509_Certificate
    {
        try {
            $response = $this->httpClient->sendRequest(
                $this->requestFactory->createRequest(
                    'GET',
                    $this->vaultBaseUrl . '/certificates/' . $this->certificateName . '/' . $this->certificateVersion
                    . '?api-version=7.1'
                )
                ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
            );
        } catch (ClientExceptionInterface $e) {
            throw new Exception('Connection error!', 0, $e);
        }

        $responseBody = (string) $response->getBody();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        $certificate = $this->json_decode($responseBody, true);
        if (!isset($certificate['cer'])) {
            throw new Exception('Couldn\'t find certificate in response.');
        }
        return new SetaPDF_Signer_X509_Certificate($certificate['cer']);
    }

    /**
     * Creates a signature from a digest using the specified key.
     *
     * The SIGN operation is applicable to asymmetric and symmetric keys stored in Azure Key Vault since this operation
     * uses the private portion of the key. This operation requires the keys/sign permission.
     *
     * @param string $digest
     * @return string
     * @throws SetaPDF_Signer_Exception
     * @see https://docs.microsoft.com/de-de/rest/api/keyvault/sign/sign
     */
    protected function sign(string $digest): string
    {
        try {
            $response = $this->httpClient->sendRequest(
                $this->requestFactory->createRequest(
                    'POST',
                    $this->vaultBaseUrl . '/keys/' . $this->certificateName . '/' . $this->certificateVersion
                    . '/sign' . '?api-version=7.1'
                )
                ->withHeader('Authorization', 'Bearer ' . $this->accessToken)
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->streamFactory->createStream(\json_encode([
                    'alg' => $this->getSignatureAlgorithm(),
                    'value' => $digest
                ])))
            );
        } catch (ClientExceptionInterface $e) {
            throw new Exception('Connection error!', 0, $e);
        }

        $responseBody = (string) $response->getBody();
        if ($response->getStatusCode() !== 200) {
            throw new Exception(\sprintf(
                'Unexpected response status code (%d). Response: %s',
                $response->getStatusCode(),
                $responseBody
            ));
        }

        $json = $this->json_decode($responseBody, true);
        if (!isset($json['value'])) {
            throw new Exception('Cannot find "value"-key in json!');
        }
        return $json['value'];
    }

    /**
     * @param $certificate
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setCertificate($certificate)
    {
        $this->padesModule->setCertificate($certificate);
    }

    /**
     * @return mixed|string
     */
    public function getCertificate()
    {
        $certificate = $this->padesModule->getCertificate();
        if ($certificate === null) {
            $certificate = $this->fetchCertificate();
            $this->padesModule->setCertificate($certificate);
        }

        return $certificate;
    }

    /**
     * Add additional certificates which are placed into the CMS structure.
     *
     * @param array|\SetaPDF_Signer_X509_Collection $extraCertificates PEM encoded certificates or pathes to PEM encoded
     *                                                                 certificates.
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setExtraCertificates($extraCertificates)
    {
        $this->padesModule->setExtraCertificates($extraCertificates);
    }

    /**
     * Adds an OCSP response which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_Ocsp_Response $ocspResponse DER encoded OCSP response or OCSP response instance.
     * @throws SetaPDF_Signer_Exception
     */
    public function addOcspResponse($ocspResponse)
    {
        $this->padesModule->addOcspResponse($ocspResponse);
    }

    /**
     * Adds an CRL which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_X509_Crl $crl
     */
    public function addCrl($crl)
    {
        $this->padesModule->addCrl($crl);
    }

    /**
     * @inheritDoc
     */
    public function createSignature(FilePath $tmpPath)
    {
        // ensure certificate
        $this->getCertificate();

        // ensure signature algorithm and pades digest
        $signatureAlgorithm = $this->getSignatureAlgorithm();
        if ($signatureAlgorithm === null) {
            $signatureAlgorithm = $this->findSignatureAlgorithm();
            $this->setSignatureAlgorithm($signatureAlgorithm);
        }

        // update CMS SignatureAlgorithmIdentifier according to Probabilistic Signature Scheme (RSASSA-PSS)
        if (\in_array($signatureAlgorithm, ['PS256', 'PS384', 'PS512'], true)) {
            // Here https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm
            // the algorihms are linked to https://tools.ietf.org/html/rfc7518#section-3.5 which says:
            // "The size of the salt value is the same size as the hash function output."
            $saltLength = 256 / 8;
            if ($signatureAlgorithm === 'PS384') {
                $saltLength = 384 / 8;
            } elseif ($signatureAlgorithm === 'PS512') {
                $saltLength = 512 / 8;
            }

            $cms = $this->padesModule->getCms();

            $signatureAlgorithmIdentifier = Asn1Element::findByPath('1/0/4/0/4', $cms);
            $signatureAlgorithmIdentifier->getChild(0)->setValue(
                Asn1Oid::encode("1.2.840.113549.1.1.10")
            );
            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(1));
            $signatureAlgorithmIdentifier->addChild(new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED,
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Asn1Oid::encode(Digest::getOid($this->padesModule->getDigest()))
                                    ),
                                    new Asn1Element(Asn1Element::NULL)
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01",
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Asn1Oid::encode('1.2.840.113549.1.1.8')
                                    ),
                                    new Asn1Element(
                                        Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                        '',
                                        [
                                            new Asn1Element(
                                                Asn1Element::OBJECT_IDENTIFIER,
                                                Asn1Oid::encode(Digest::getOid(
                                                    $this->padesModule->getDigest()
                                                ))
                                            ),
                                            new Asn1Element(Asn1Element::NULL)
                                        ]
                                    )
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02", '',
                        [
                            new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
                        ]
                    )
                ]
            ));
        }

        // get the hash data from the module
        $hashData = $this->padesModule->getDataToSign($tmpPath);
        $padesDigest = $this->padesModule->getDigest();

        $digest = $this->base64url_encode(hash($padesDigest, $hashData, true));
        $signatureResponse = $this->sign($digest);
        $signatureValue = $this->base64url_decode($signatureResponse);

        if (\in_array($signatureAlgorithm, ['ES256', 'ES256K', 'ES384', 'ES512'], true)) {
            // THIS NEEDS TO BE USED TO FIX EC SIGNATURES
            $len = strlen($signatureValue);

            $s = substr($signatureValue, 0, $len / 2);
            if (ord($s[0]) & 0x80) { // ensure positive integers
                $s = "\0" . $s;
            }
            $r = substr($signatureValue, $len / 2);
            if (ord($r[0]) & 0x80) { // ensure positive integers
                $r = "\0" . $r;
            }

            $signatureValue = new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(Asn1Element::INTEGER, $s),
                    new Asn1Element(Asn1Element::INTEGER, $r),
                ]
            );
        }

        // pass it to the module
        $this->padesModule->setSignatureValue((string)$signatureValue);
        return (string) $this->padesModule->getCms();
    }

    /**
     * @inheritDoc
     */
    public function updateSignatureDictionary(Dictionary $dictionary)
    {
        $this->padesModule->updateSignatureDictionary($dictionary);
    }

    /**
     * @inheritDoc
     */
    public function updateDocument(Document $document)
    {
        $this->padesModule->updateDocument($document);
    }

    /**
     * Get the complete Cryptographic Message Syntax structure.
     *
     * @return Asn1Element
     * @throws SetaPDF_Signer_Exception
     */
    public function getCms()
    {
        return $this->padesModule->getCms();
    }
}
