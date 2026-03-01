<?php

namespace TomStGeorge\SilverStripeWordpressLogins\Service;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use SilverStripe\Core\Environment;

class WordPressClient
{
    /**
     * Base URL to the WordPress site, e.g. http://shop.local.test
     *
     * Configure in .env, for example:
     *   FATHOM_WORDPRESS_BASE_URL="http://shop.local.test"
     */
    protected function getBaseUrl(): ?string
    {
        $base = Environment::getEnv('FATHOM_WORDPRESS_BASE_URL');
        if (!$base) {
            return null;
        }

        return rtrim((string) $base, '/');
    }

    /**
     * Internal auth shared secret for securing requests to WordPress.
     *
     * Configure in .env, for example:
     *   FATHOM_INTERNAL_AUTH_SHARED_SECRET="a-long-random-string"
     *
     * Falls back to FATHOM_DUAL_LOGIN_SHARED_SECRET if not set.
     */
    protected function getSharedSecret(): ?string
    {
        $secret = Environment::getEnv('FATHOM_INTERNAL_AUTH_SHARED_SECRET')
            ?: Environment::getEnv('FATHOM_DUAL_LOGIN_SHARED_SECRET');

        if (!$secret) {
            return null;
        }

        return (string) $secret;
    }

    protected function getVerifyPath(): string
    {
        $path = Environment::getEnv('FATHOM_WORDPRESS_VERIFY_PATH');
        if ($path) {
            return $path;
        }

        return '/wp-json/internal-auth/verify';
    }

    protected function getUpsertPath(): string
    {
        $path = Environment::getEnv('FATHOM_WORDPRESS_UPSERT_PATH');
        if ($path) {
            return $path;
        }

        return '/wp-json/internal-auth/upsert';
    }

    /**
     * Verify credentials against WordPress' internal auth API.
     */
    public function verifyCredentials(string $email, string $password): bool
    {
        $base = $this->getBaseUrl();
        $secret = $this->getSharedSecret();

        if (!$base || !$secret) {
            return false;
        }

        $client = new Client([
            'timeout' => 5.0,
        ]);

        try {
            $response = $client->request('POST', $base . $this->getVerifyPath(), [
                'headers' => [
                    'X-Fathom-Internal-Auth' => $secret,
                    'Accept' => 'application/json',
                ],
                'json' => [
                    'email' => $email,
                    'password' => $password,
                ],
            ]);
        } catch (GuzzleException $e) {
            return false;
        }

        if ($response->getStatusCode() !== 200) {
            return false;
        }

        $body = (string) $response->getBody();
        $data = json_decode($body, true);

        if (!is_array($data)) {
            return false;
        }

        return !empty($data['success']);
    }

    /**
     * Ensure a matching WordPress user exists with the given password.
     */
    public function upsertUser(string $email, string $password, ?string $firstName = null, ?string $lastName = null): bool
    {
        $base = $this->getBaseUrl();
        $secret = $this->getSharedSecret();

        if (!$base || !$secret) {
            return false;
        }

        $client = new Client([
            'timeout' => 5.0,
        ]);

        $payload = [
            'email' => $email,
            'password' => $password,
        ];

        if ($firstName !== null) {
            $payload['first_name'] = $firstName;
        }
        if ($lastName !== null) {
            $payload['last_name'] = $lastName;
        }

        try {
            $response = $client->request('POST', $base . $this->getUpsertPath(), [
                'headers' => [
                    'X-Fathom-Internal-Auth' => $secret,
                    'Accept' => 'application/json',
                ],
                'json' => $payload,
            ]);
        } catch (GuzzleException $e) {
            return false;
        }

        if ($response->getStatusCode() !== 200) {
            return false;
        }

        $body = (string) $response->getBody();
        $data = json_decode($body, true);

        if (!is_array($data)) {
            return false;
        }

        return !empty($data['success']);
    }
}

