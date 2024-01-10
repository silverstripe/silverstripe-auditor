<?php

namespace SilverStripe\Auditor;

use Psr\Log\LoggerInterface;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\MFA\Authenticator\LoginHandler;
use SilverStripe\MFA\Method\MethodInterface;
use SilverStripe\MFA\Service\RegisteredMethodManager;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Member;

/**
 * Provides logging actions on extension hooks from certain silverstripe/mfa actions.
 *
 * @extends DataExtension<LoginHandler|RegisteredMethodManager>
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
        $this->getAuditLogger()->info(
            sprintf(
                '"%s" (ID: %s) successfully verified using MFA method',
                $member->Email ?: $member->Title,
                $member->ID
            ),
            ['method' => get_class($method)]
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
            'method' => get_class($method),
        ];
        if ($lockOutAfterCount = $member->config()->get('lock_out_after_incorrect_logins')) {
            // Add information about how many attempts have been made
            $context['attempts'] = $member->FailedLoginCount;
            $context['attempt_limit'] = $lockOutAfterCount;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) failed to verify using MFA method',
            $member->Email ?: $member->Title,
            $member->ID
        ), $context);
    }

    /**
     * A user has skipped MFA registration when it is enabled but optional, or within a grace period
     *
     * @param Member $member
     */
    public function onSkipRegistration(Member $member)
    {
        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) skipped MFA registration',
            $member->Email ?: $member->Title,
            $member->ID
        ));
    }

    /**
     * @param Member $member
     * @param MethodInterface $method
     */
    public function onRegisterMethod(Member $member, $method)
    {
        $context = [
            'method' => get_class($method),
        ];

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) registered MFA method',
            $member->Email ?: $member->Title,
            $member->ID
        ), $context);
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
            'method' => get_class($method),
        ];

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) failed registering new MFA method',
            $member->Email ?: $member->Title,
            $member->ID
        ), $context);
    }

    /**
     * @return LoggerInterface
     */
    protected function getAuditLogger()
    {
        return Injector::inst()->get('AuditLogger');
    }
}
