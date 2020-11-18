<?php

namespace setasign\SetaPDF\Signer\Module\AzureKeyVault;

use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use SetaPDF_Core_Document;
use SetaPDF_Core_Reader_FilePath;
use SetaPDF_Core_Type_Dictionary;
use SetaPDF_Signer_Asn1_Element;
use SetaPDF_Signer_Asn1_Oid;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Exception;
use SetaPDF_Signer_Signature_DictionaryInterface;
use SetaPDF_Signer_Signature_DocumentInterface;
use SetaPDF_Signer_Signature_Module_ModuleInterface;
use SetaPDF_Signer_Signature_Module_Pades;
use SetaPDF_Signer_X509_Certificate;

class Module implements
    SetaPDF_Signer_Signature_Module_ModuleInterface,
    SetaPDF_Signer_Signature_DictionaryInterface,
    SetaPDF_Signer_Signature_DocumentInterface
{
    /**
     * @var string
     */
    private $vaultBaseUrl;

    /**
     * @var string
     */
    private $certificateName;

    /**
     * @var string
     */
    private $certificateVersion;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var StreamFactoryInterface
     */
    private $streamFactory;

    /**
     * @var SetaPDF_Signer_Signature_Module_Pades
     */
    private $padesModule;

    /**
     * @var null|string
     */
    private $accessToken;

    /**
     * @var null|string
     */
    private $signatureAlgorithm;

    /**
     * Module constructor.
     *
     * @param string $vaultBaseUrl
     * @param string $certificateName
     * @param string $certificateVersion
     * @param ClientInterface $httpClient
     * @param RequestFactoryInterface $requestFactory
     * @param StreamFactoryInterface $streamFactory
     */
    public function __construct(
        $vaultBaseUrl,
        $certificateName,
        $certificateVersion,
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
     * @param string $digest
     * @see SetaPDF_Signer_Signature_Module_Pades::setDigest()
     */
    public function setDigest($digest)
    {
        $this->padesModule->setDigest($digest);
    }

    public function getDigest()
    {
        return $this->padesModule->getDigest();
    }

    /**
     * @param string $algorithm
     * @see https://docs.microsoft.com/de-de/rest/api/keyvault/sign/sign
     */
    public function setSignatureAlgorithm($algorithm)
    {
        $this->signatureAlgorithm = $algorithm;
    }

    /**
     * @return string|null
     */
    public function getSignatureAlgorithm()
    {
        return $this->signatureAlgorithm;
    }

    /**
     * @return string
     * @throws SetaPDF_Signer_Exception
     */
    public function findSignatureAlgorithm()
    {
        // ensure certificate
        $certificate = $this->padesModule->getCertificate();
        if ($certificate === null) {
            $certificate = $this->fetchCertificate();
            $this->padesModule->setCertificate($certificate);
        }

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
     */
    protected function base64url_decode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * @param string $data
     * @return string
     */
    protected function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * json_decode wrapper to handle invalid json. Can be removed with php7.3 and JSON_THROW_ON_ERROR
     *
     * @param string $json
     * @param bool $assoc
     * @param int $depth
     * @param int $options
     * @return mixed
     */
    protected function json_decode($json, $assoc = false, $depth = 512, $options = 0)
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
     * @param string $tenant
     * @param string $appClientId
     * @param string $appClientSecret
     * @param string $scope
     * @return array{accessToken: string, expires: int}
     * @throws Exception
     * @see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#first-case-access-token-request-with-a-shared-secret
     */
    public function createTokenBySharedSecret(
        $tenant,
        $appClientId,
        $appClientSecret,
        $scope = 'https://vault.azure.net/.default'
    ) {
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
     * @return SetaPDF_Signer_X509_Certificate
     * @throws Exception
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @see https://docs.microsoft.com/de-de/rest/api/keyvault/getcertificate/getcertificate
     */
    public function fetchCertificate()
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
     * @param string $digest
     * @return string
     * @throws SetaPDF_Signer_Exception
     * @see https://docs.microsoft.com/de-de/rest/api/keyvault/sign/sign
     */
    protected function sign($digest)
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

    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;
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
     * @param SetaPDF_Core_Reader_FilePath $tmpPath
     * @return string|void
     * @throws \SetaPDF_Signer_Exception
     */
    public function createSignature(SetaPDF_Core_Reader_FilePath $tmpPath)
    {
        // ensure certificate
        $certificate = $this->padesModule->getCertificate();
        if ($certificate === null) {
            $certificate = $this->fetchCertificate();
            $this->padesModule->setCertificate($certificate);
        }

        // ensure signature algorithm and pades digest
        $signatureAlgorithm = $this->getSignatureAlgorithm();
        if ($signatureAlgorithm === null) {
            $signatureAlgorithm = $this->findSignatureAlgorithm();
            $this->setSignatureAlgorithm($signatureAlgorithm);
        }

        // update CMS SignatureAlgorithmIdentifier according to Probabilistic Signature Scheme (RSASSA-PSS)
        if (\in_array($signatureAlgorithm, ['PS256', 'PS384', 'PS512'], true)) {
            $cms = $this->padesModule->getCms();

            $signatureAlgorithmIdentifier = SetaPDF_Signer_Asn1_Element::findByPath('1/0/4/0/4', $cms);
            $signatureAlgorithmIdentifier->getChild(0)->setValue(SetaPDF_Signer_Asn1_Oid::encode("1.2.840.113549.1.1.10"));
            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(1));
            $signatureAlgorithmIdentifier->addChild(new SetaPDF_Signer_Asn1_Element(
                SetaPDF_Signer_Asn1_Element::SEQUENCE | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                [
                    new SetaPDF_Signer_Asn1_Element(
                        SetaPDF_Signer_Asn1_Element::TAG_CLASS_CONTEXT_SPECIFIC | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                        [
                            new SetaPDF_Signer_Asn1_Element(
                                SetaPDF_Signer_Asn1_Element::SEQUENCE | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                                [
                                    new SetaPDF_Signer_Asn1_Element(
                                        SetaPDF_Signer_Asn1_Element::OBJECT_IDENTIFIER,
                                        SetaPDF_Signer_Asn1_Oid::encode(Digest::getOid($this->padesModule->getDigest()))
                                    ),
                                    new SetaPDF_Signer_Asn1_Element(SetaPDF_Signer_Asn1_Element::NULL)
                                ]
                            )
                        ]
                    ),
                    new SetaPDF_Signer_Asn1_Element(
                        SetaPDF_Signer_Asn1_Element::TAG_CLASS_CONTEXT_SPECIFIC | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED | "\x01", '',
                        [
                            new SetaPDF_Signer_Asn1_Element(
                                SetaPDF_Signer_Asn1_Element::SEQUENCE | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                                [
                                    new SetaPDF_Signer_Asn1_Element(
                                        SetaPDF_Signer_Asn1_Element::OBJECT_IDENTIFIER,
                                        SetaPDF_Signer_Asn1_Oid::encode('1.2.840.113549.1.1.8')
                                    ),
                                    new SetaPDF_Signer_Asn1_Element(
                                        SetaPDF_Signer_Asn1_Element::SEQUENCE | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED, '',
                                        [
                                            new SetaPDF_Signer_Asn1_Element(
                                                SetaPDF_Signer_Asn1_Element::OBJECT_IDENTIFIER,
                                                SetaPDF_Signer_Asn1_Oid::encode(Digest::getOid($this->padesModule->getDigest()))
                                            ),
                                            new SetaPDF_Signer_Asn1_Element(SetaPDF_Signer_Asn1_Element::NULL)
                                        ]
                                    )
                                ]
                            )
                        ]
                    ),
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

            $signatureValue = new SetaPDF_Signer_Asn1_Element(
                SetaPDF_Signer_Asn1_Element::SEQUENCE | SetaPDF_Signer_Asn1_Element::IS_CONSTRUCTED,
                '',
                [
                    new SetaPDF_Signer_Asn1_Element(SetaPDF_Signer_Asn1_Element::INTEGER, $s),
                    new SetaPDF_Signer_Asn1_Element(SetaPDF_Signer_Asn1_Element::INTEGER, $r),
                ]
            );
        }

        // pass it to the module
        $this->padesModule->setSignatureValue((string)$signatureValue);
        return (string) $this->padesModule->getCms();
    }

    public function updateSignatureDictionary(SetaPDF_Core_Type_Dictionary $dictionary)
    {
        $this->padesModule->updateSignatureDictionary($dictionary);
    }

    public function updateDocument(SetaPDF_Core_Document $document)
    {
        $this->padesModule->updateDocument($document);
    }

    public function getCms()
    {
        return $this->padesModule->getCms();
    }
}
