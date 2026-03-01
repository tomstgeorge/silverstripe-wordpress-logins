<?php

namespace TomStGeorge\SilverStripeWordpressLogins\Extension;

use TomStGeorge\SilverStripeWordpressLogins\Service\WordPressClient;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;

class LoginHandlerExtension extends Extension
{
    /**
     * After a successful login, push the credentials to WordPress so its user
     * database stays in sync.
     *
     * @param Member $member
     */
    public function afterLogin(Member $member): void
    {
        $enabled = Environment::getEnv('SILVERSTRIPE_ENABLE_SS_TO_WP_SYNC_ON_LOGIN');
        if (!$enabled || strtolower((string) $enabled) === 'false') {
            return;
        }

        $owner = $this->getOwner();
        $request = $owner ? $owner->getRequest() : null;
        if (!$request) {
            return;
        }

        $password = (string) $request->postVar('Password');
        $email = (string) $member->Email;

        if ($email === '' || $password === '') {
            error_log('[SS Dual Login] afterLogin: missing email or password');
            return;
        }

        /** @var WordPressClient $client */
        $client = Injector::inst()->get(WordPressClient::class);
        $result = $client->upsertUser($email, $password, $member->FirstName, $member->Surname);
        error_log('[SS Dual Login] afterLogin: upsertUser for ' . $email . ' result: ' . var_export($result, true));
    }

    /**
     * Fallback: If login fails because Member does not exist, try WP verify and create Member if valid.
     * Call this from your login handler if Member is missing.
     *
     * @param string $email
     * @param string $password
     * @return Member|null
     */
    public function tryCreateMemberFromWordPress($email, $password)
    {
        /** @var WordPressClient $client */
        $client = Injector::inst()->get(WordPressClient::class);
        $verified = $client->verifyCredentials($email, $password);
        error_log('[SS Dual Login] tryCreateMemberFromWordPress: verifyCredentials for ' . $email . ' result: ' . var_export($verified, true));
        if ($verified) {
            $member = Member::create();
            $member->Email = $email;
            $member->changePassword($password);
            $member->write();
            error_log('[SS Dual Login] tryCreateMemberFromWordPress: created Member for ' . $email);
            return $member;
        }
        return null;
    }
}
