<?php

namespace Fathom\SilverStripeWordpressLogins\Extension;

use Fathom\SilverStripeWordpressLogins\Service\WordPressClient;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;

class MemberPasswordSyncExtension extends Extension
{
    /**
     * Called after a password has been changed via Member::changePassword().
     *
     * @param string $password
     * @param ValidationResult $result
     */
    public function onAfterChangePassword(string $password, ValidationResult $result): void
    {
        if (!$result->isValid()) {
            return;
        }

        $enabled = Environment::getEnv('FATHOM_ENABLE_SS_TO_WP_SYNC_ON_PASSWORD_CHANGE');
        if (!$enabled || strtolower((string) $enabled) === 'false') {
            return;
        }

        $member = $this->getOwner();
        if (!$member || !$member->Email) {
            error_log('[SS Dual Login] onAfterChangePassword: missing member or email');
            return;
        }

        /** @var WordPressClient $client */
        $client = Injector::inst()->get(WordPressClient::class);
        $result = $client->upsertUser((string) $member->Email, $password, $member->FirstName, $member->Surname);
        error_log('[SS Dual Login] onAfterChangePassword: upsertUser for ' . $member->Email . ' result: ' . var_export($result, true));
    }
}
