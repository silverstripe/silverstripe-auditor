<?php

namespace SilverStripe\Auditor;

use Psr\Log\LoggerInterface;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Method\MethodInterface;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Member;

/**
 * Provides logging actions on extension hooks from certain silverstripe/mfa actions.
 */
class AuditHookMFA extends DataExtension
{
    /**
     * A successful login using an MFA method
     *
     * @param Member $member
     * @param MethodInterface $method
     */
    public function onMethodVerificationSuccess(Member $member, $method)
    {
        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'method' => get_class($method),
            'type' => AuditedEventType::NOTICE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) successfully verified using MFA method',
            $context,
        );
    }

    /**
     * A failed login using an MFA method
     *
     * @param Member $member
     * @param MethodInterface $method
     */
    public function onMethodVerificationFailure(Member $member, $method)
    {
        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'method' => get_class($method),
            'type' => AuditedEventType::NOTICE,
        ];

        if ($lockOutAfterCount = $member->config()->get('lock_out_after_incorrect_logins')) {
            // Add information about how many attempts have been made
            $context['attempts'] = $member->FailedLoginCount;
            $context['attempt_limit'] = $lockOutAfterCount;
        }

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) failed to verify using MFA method',
            $context,
        );
    }

    /**
     * A user has skipped MFA registration when it is enabled but optional, or within a grace period
     *
     * @param Member $member
     */
    public function onSkipRegistration(Member $member)
    {
        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'type' => AuditedEventType::NOTICE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) skipped MFA registration',
            $context,
        );
    }

    /**
     * @param Member $member
     * @param MethodInterface $method
     */
    public function onRegisterMethod(Member $member, $method)
    {
        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'method' => get_class($method),
            'type' => AuditedEventType::CREATE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) registered MFA method',
            $context,
        );
    }

    /**
     * A user has failed to register an MFA method against their account
     *
     * @param Member $member
     * @param MethodInterface $method
     */
    public function onRegisterMethodFailure(Member $member, $method)
    {
        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'method' => get_class($method),
            'type' => AuditedEventType::NOTICE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) failed registering new MFA method',
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
