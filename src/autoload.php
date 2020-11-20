<?php

declare(strict_types=1);

// @phpstan-ignore-next-line
spl_autoload_register(function ($class) {
    $namespace = 'setasign\SetaPDF\Signer\Module\AzureKeyVault\\';
    if (strpos($class, $namespace) === 0) {
        $filename = str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($namespace))) . '.php';
        $fullpath = __DIR__ . DIRECTORY_SEPARATOR . $filename;

        if (is_file($fullpath)) {
            /** @noinspection PhpIncludeInspection */
            require_once $fullpath;
        }
    }
});
