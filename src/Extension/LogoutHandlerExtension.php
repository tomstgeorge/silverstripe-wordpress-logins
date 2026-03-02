<?php

namespace TomStGeorge\SilverStripeWordpressLogins\Extension;

use TomStGeorge\SilverStripeWordpressLogins\Service\TokenService;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Security;

class LogoutHandlerExtension extends Extension
{
    private const SESSION_PENDING_WP_LOGOUT_TOKEN = 'SilverStripeWordpressLogins.PendingWPLogoutToken';

    public function beforeLogout(): void
    {
        $enabled = Environment::getEnv('SILVERSTRIPE_ENABLE_SS_TO_WP_SYNC_ON_LOGIN');
        if ($enabled !== null && strtolower((string) $enabled) === 'false') {
            return;
        }

        $request = $this->owner->getRequest();
        if (!$request instanceof HTTPRequest) {
            return;
        }

        $member = Security::getCurrentUser();
        if (!$member || !$member->exists() || !$member->Email) {
            return;
        }

        /** @var TokenService $tokens */
        $tokens = Injector::inst()->get(TokenService::class);
        $token = $tokens->generateToken((string) $member->Email);
        if (!$token) {
            return;
        }

        $request->getSession()->set(self::SESSION_PENDING_WP_LOGOUT_TOKEN, $token);
    }
}
