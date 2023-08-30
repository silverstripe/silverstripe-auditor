<?php

namespace SilverStripe\Auditor;

use Psr\Log\LoggerInterface;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Security;
use SilverStripe\SessionManager\Models\LoginSession;

/**
 * Provides logging actions on extension hooks from certain silverstripe/session-manager actions.
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

        $context = [
            'login_session_id' => $loginSession->ID,
            'member_email_or_title' => $member->Email ?: $member->Title,
            'member_id' => $member->ID,
            'actor_email_or_title' => $currentUser->Email ?: $currentUser->Title,
            'actor_id' => $currentUser->ID,
            'crud' => AuditedEventType::DELETE,
        ];

        $this->getAuditLogger()->info(
            'Login session (ID: {login_session_id}) for Member "{member_email_or_title}" (ID: {member_id}) is being removed by Member "{actor_email_or_title}" (ID: {actor_id})',
            $context,
        );
    }

    /**
     * @return LoggerInterface
     */
    protected function getAuditLogger()
    {
        return Injector::inst()->get('AuditLogger');
    }
}
