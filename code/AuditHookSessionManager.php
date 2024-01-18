<?php

namespace SilverStripe\Auditor;

use Psr\Log\LoggerInterface;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Security;
use SilverStripe\SessionManager\Controllers\LoginSessionController;
use SilverStripe\SessionManager\Models\LoginSession;

/**
 * Provides logging actions on extension hooks from certain silverstripe/session-manager actions.
 *
 * @extends DataExtension<LoginSessionController>
 */
class AuditHookSessionManager extends DataExtension
{
    /**
     * Login session for a member is being removed
     *
     * @param LoginSession $loginSession
     */
    public function onBeforeRemoveLoginSession(LoginSession $loginSession)
    {
        $member = $loginSession->Member();
        $currentUser = Security::getCurrentUser();
        if (is_null($member) || $member->ID === 0 || is_null($currentUser) || $currentUser->ID === 0) {
            return;
        }
        $this->getAuditLogger()->info(sprintf(
            'Login session (ID: %s) for Member "%s" (ID: %s) is being removed by Member "%s" (ID: %s)',
            $loginSession->ID,
            $member->Email ?: $member->Title,
            $member->ID,
            $currentUser->Email ?: $currentUser->Title,
            $currentUser->ID
        ));
    }

    /**
     * @return LoggerInterface
     */
    protected function getAuditLogger()
    {
        return Injector::inst()->get('AuditLogger');
    }
}
