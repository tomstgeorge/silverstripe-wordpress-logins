<?php

namespace Fathom\SilverStripeWordpressLogins\Controller;

use Fathom\SilverStripeWordpressLogins\Service\TokenService;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class AutoLoginController extends Controller
{
    private static $url_segment = 'auto-login';

    private static $allowed_actions = [
        'index',
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        $token = (string) $request->getVar('token');
        $redirect = (string) $request->getVar('redirect');

        /** @var TokenService $tokens */
        $tokens = Injector::inst()->get(TokenService::class);
        $payload = $tokens->parseAndVerify($token);

        if (!$payload) {
            return $this->forbidden('Invalid or expired auto-login token.');
        }

        $email = $payload['email'] ?? null;
        if (!$email) {
            return $this->forbidden('Invalid token payload.');
        }

        /** @var Member|null $member */
        $member = Member::get()->filter('Email', $email)->first();

        if (!$member) {
            $member = Member::create();
            $member->Email = $email;
            try {
                $member->write();
            } catch (ValidationException $e) {
                return $this->forbidden('Unable to create member for auto-login.');
            }
        }

        if (!$member->canLogin()) {
            return $this->forbidden('Member is not allowed to log in.');
        }

        /** @var IdentityStore $identityStore */
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $identityStore->logIn($member, false, $request);
        Security::setCurrentUser($member);

        $safeRedirect = $this->sanitizeRedirect($redirect);
        if ($safeRedirect) {
            return $this->redirect($safeRedirect);
        }

        $response = HTTPResponse::create();
        $response->setStatusCode(200);
        $response->addHeader('Content-Type', 'text/html; charset=utf-8');
        $response->setBody('<!DOCTYPE html><html><head><meta charset="utf-8"><title>OK</title></head><body>OK</body></html>');
        return $response;
    }

    protected function forbidden(string $message): HTTPResponse
    {
        $response = HTTPResponse::create();
        $response->setStatusCode(403);
        $response->addHeader('Content-Type', 'text/plain; charset=utf-8');
        $response->setBody($message);
        return $response;
    }

    protected function sanitizeRedirect(string $redirect): ?string
    {
        $redirect = trim($redirect);
        if ($redirect === '') {
            return null;
        }

        // Absolute URL: only allow same host.
        if (preg_match('#^https?://#i', $redirect)) {
            $current = $this->getRequest();
            if (!$current) {
                return null;
            }

            $currentHost = $current->getHeader('Host') ?: $current->getIP();
            $targetHost = parse_url($redirect, PHP_URL_HOST);

            if (!$currentHost || !$targetHost || strcasecmp($currentHost, $targetHost) !== 0) {
                return null;
            }

            return $redirect;
        }

        if ($redirect[0] !== '/') {
            $redirect = '/' . $redirect;
        }

        return $this->getRequest()->getSchemeAndHost() . $redirect;
    }
}

