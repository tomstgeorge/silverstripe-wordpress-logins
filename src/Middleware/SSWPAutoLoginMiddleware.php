<?php

namespace TomStGeorge\SilverStripeWordpressLogins\Middleware;

use TomStGeorge\SilverStripeWordpressLogins\Service\TokenService;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Security;

class SSWPAutoLoginMiddleware implements HTTPMiddleware
{
    public function process(HTTPRequest $request, callable $delegate)
    {
        $response = $delegate($request);

        if (!$response instanceof HTTPResponse) {
            return $response;
        }

        if (!$this->shouldInject($request, $response)) {
            return $response;
        }

        $member = Security::getCurrentUser();
        if (!$member || !$member->exists() || !$member->Email) {
            return $response;
        }

        /** @var TokenService $tokens */
        $tokens = Injector::inst()->get(TokenService::class);
        $token = $tokens->generateToken((string) $member->Email);
        if (!$token) {
            return $response;
        }

        $base = Environment::getEnv('SILVERSTRIPE_WORDPRESS_PUBLIC_BASE_URL')
            ?: Environment::getEnv('SILVERSTRIPE_WORDPRESS_BASE_URL');
        if (!$base) {
            return $response;
        }

        $base = rtrim((string) $base, '/');
        $redirect = (string) (Environment::getEnv('SILVERSTRIPE_WORDPRESS_AUTOLOGIN_REDIRECT') ?: '/my-account/');
        if ($redirect === '' || $redirect[0] !== '/') {
            $redirect = '/' . ltrim($redirect, '/');
        }

        $src = $base . '/?silverstripe_wp_autologin=1&token=' . rawurlencode($token) . '&redirect=' . rawurlencode($redirect);
        $iframe = '<iframe src="' . htmlspecialchars($src, ENT_QUOTES, 'UTF-8') . '" style="display:none !important;width:0;height:0;border:0;" aria-hidden="true" tabindex="-1" data-silverstripe-wp-autologin="1"></iframe>';

        $body = (string) $response->getBody();
        if ($body === '' || strpos($body, 'data-silverstripe-wp-autologin="1"') !== false) {
            return $response;
        }

        if (stripos($body, '</head>') !== false) {
            $body = preg_replace('/<\/head>/i', $iframe . '</head>', $body, 1) ?? $body;
        } elseif (stripos($body, '</body>') !== false) {
            $body = preg_replace('/<\/body>/i', $iframe . '</body>', $body, 1) ?? $body;
        } else {
            $body .= $iframe;
        }

        $response->setBody($body);
        return $response;
    }

    protected function shouldInject(HTTPRequest $request, HTTPResponse $response): bool
    {
        $enabled = Environment::getEnv('SILVERSTRIPE_ENABLE_SS_TO_WP_SYNC_ON_LOGIN');
        if ($enabled !== null && strtolower((string) $enabled) === 'false') {
            return false;
        }

        if (!$request->isGET()) {
            return false;
        }

        if ($response->getStatusCode() !== 200) {
            return false;
        }

        $contentType = (string) $response->getHeader('Content-Type');
        if ($contentType !== '' && stripos($contentType, 'text/html') === false) {
            return false;
        }

        $path = (string) $request->getURL();
        if (stripos($path, 'silverstripe-auth') !== false || stripos($path, 'silverstripe-auto-login') !== false) {
            return false;
        }

        return true;
    }
}
