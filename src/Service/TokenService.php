<?php

namespace Fathom\SilverStripeWordpressLogins\Service;

use SilverStripe\Core\Environment;

class TokenService
{
    /**
     * Get the shared secret used for signing auto-login tokens.
     *
     * This should be configured in your SilverStripe .env, for example:
     *   FATHOM_DUAL_LOGIN_SHARED_SECRET="a-long-random-string"
     */
    protected function getSharedSecret(): ?string
    {
        $secret = Environment::getEnv('FATHOM_DUAL_LOGIN_SHARED_SECRET');

        if (!$secret) {
            return null;
        }

        return (string) $secret;
    }

    /**
     * Token time-to-live (seconds).
     */
    protected function getTokenTTL(): int
    {
        $ttl = Environment::getEnv('FATHOM_DUAL_LOGIN_TOKEN_TTL');

        if (is_numeric($ttl) && (int) $ttl > 0) {
            return (int) $ttl;
        }

        // Default: 5 minutes.
        return 300;
    }

    /**
     * Generate a short-lived, HMAC-signed token for the given email.
     *
     * Format matches the WordPress plugin:
     *   base64url(payload_json) . '.' . base64url(hmac_sha256(payload_b64, secret))
     * Payload is JSON: { email, issued_at, expires_at, nonce }.
     */
    public function generateToken(string $email): ?string
    {
        $secret = $this->getSharedSecret();

        if (!$secret) {
            return null;
        }

        $email = trim(mb_strtolower($email ?? ''));

        if ($email == '') {
            return null;
        }

        $now = time();
        $ttl = $this->getTokenTTL();

        $payload = [
            'email' => $email,
            'issued_at' => $now,
            'expires_at' => $now + $ttl,
            'nonce' => bin2hex(random_bytes(16)),
        ];

        $payloadJson = json_encode($payload);
        if (!is_string($payloadJson)) {
            return null;
        }

        $payloadB64 = $this->base64urlEncode($payloadJson);
        $signature = hash_hmac('sha256', $payloadB64, $secret, true);
        $sigB64 = $this->base64urlEncode($signature);

        return $payloadB64 . '.' . $sigB64;
    }

    /**
     * Parse and verify a token.
     *
     * Returns the payload array on success, or null on failure.
     */
    public function parseAndVerify(string $token): ?array
    {
        $secret = $this->getSharedSecret();

        if (!$secret) {
            return null;
        }

        if ($token === '') {
            return null;
        }

        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return null;
        }

        [$payloadB64, $sigB64] = $parts;

        $payloadJson = $this->base64urlDecode($payloadB64);
        $signature = $this->base64urlDecode($sigB64);

        if ($payloadJson === false || $signature === false) {
            return null;
        }

        $expectedSig = hash_hmac('sha256', $payloadB64, $secret, true);
        if (!hash_equals($expectedSig, $signature)) {
            return null;
        }

        $payload = json_decode($payloadJson, true);
        if (!is_array($payload)) {
            return null;
        }

        if (empty($payload['email']) || empty($payload['issued_at']) || empty($payload['expires_at']) || empty($payload['nonce'])) {
            return null;
        }

        $now = time();

        // Basic sanity checks on times.
        if ($payload['issued_at'] > $now + 300) {
            return null;
        }

        if ($payload['expires_at'] < $now) {
            return null;
        }

        $payload['email'] = trim(mb_strtolower((string) $payload['email']));

        return $payload;
    }

    protected function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @return string|false
     */
    protected function base64urlDecode(string $data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            return false;
        }

        return $decoded;
    }
}

