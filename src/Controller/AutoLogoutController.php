<?php

namespace TomStGeorge\SilverStripeWordpressLogins\Controller;

use TomStGeorge\SilverStripeWordpressLogins\Service\TokenService;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Security;

class AutoLogoutController extends Controller
{
    private static $url_segment = 'silverstripe-auto-logout';

    private static $allowed_actions = [
        'index',
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        $token = (string) $request->getVar('token');

        /** @var TokenService $tokens */
        $tokens = Injector::inst()->get(TokenService::class);
        $payload = $tokens->parseAndVerify($token);

        if (!$payload) {
            return $this->forbidden('Invalid or expired auto-logout token.');
        }

        Injector::inst()->get(IdentityStore::class)->logOut($request);
        Security::setCurrentUser(null);

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
}
