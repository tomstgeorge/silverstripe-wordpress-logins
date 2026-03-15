<?php

namespace TomStGeorge\SilverStripeWordpressLogins\Authenticator;

use TomStGeorge\SilverStripeWordpressLogins\Extension\LoginHandlerExtension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;
use SilverStripe\Security\MemberAuthenticator\LoginHandler;

class WordPressAuthenticator extends MemberAuthenticator
{
    /**
     * Attempt to authenticate the user.
     * If standard MemberAuthenticator fails, try to create from WordPress.
     *
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult $result
     * @return Member|null
     */
    public function authenticate(array $data, \SilverStripe\Control\HTTPRequest $request, \SilverStripe\ORM\ValidationResult &$result = null)
    {
        error_log('[SS Dual Login] WordPressAuthenticator::authenticate called for ' . ($data['Email'] ?? 'unknown'));
        
        // Try standard authentication first
        $member = parent::authenticate($data, $request, $result);

        if ($member) {
            error_log('[SS Dual Login] Standard SS login success for ' . $data['Email']);
            return $member;
        }

        error_log('[SS Dual Login] Standard SS login failed, trying WP fallback');

        // If it failed because user doesn't exist locally, try WordPress fallback
        $email = $data['Email'] ?? null;
        $password = $data['Password'] ?? null;

        if ($email && $password) {
            /** @var LoginHandlerExtension $extension */
            $extension = Injector::inst()->get(LoginHandlerExtension::class);
            
            // This will verify against WP and create the Member if valid
            $member = $extension->tryCreateMemberFromWordPress($email, $password);
            
            if ($member) {
                error_log('[SS Dual Login] WP fallback success for ' . $email);
                return $member;
            }
        }

        error_log('[SS Dual Login] WP fallback failed');
        return null;
    }

    public function getLoginHandler($link)
    {
        return LoginHandler::create($link, $this);
    }
}
