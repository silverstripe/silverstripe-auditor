<?php

namespace SilverStripe\Auditor\Tests;

use PHPUnit\Framework\MockObject\MockObject;
use SilverStripe\Auditor\Tests\AuditHookTest\Logger;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\Authenticator\LoginHandler;
use SilverStripe\MFA\Authenticator\MemberAuthenticator;
use SilverStripe\MFA\Method\MethodInterface;
use SilverStripe\Security\Member;

class AuditHookMFATest extends SapphireTest
{
    protected static $fixture_file = 'AuditHookMFATest.yml';

    /**
     * @var Logger
     */
    protected $writer;

    /**
     * @var LoginHandler
     */
    protected $handler;

    /**
     * @var Member
     */
    protected $member;

    /**
     * @var MethodInterface|MockObject
     */
    protected $method;

    protected function setUp(): void
    {
        parent::setUp();

        if (!interface_exists(MethodInterface::class)) {
            $this->markTestSkipped('This test requires the silverstripe/mfa module to be installed');
            return;
        }

        $this->writer = new Logger;

        // Phase singleton out, so the message log is purged.
        Injector::inst()->unregisterNamedObject('AuditLogger');
        Injector::inst()->registerService($this->writer, 'AuditLogger');

        $this->handler = new LoginHandler('foo', $this->createMock(MemberAuthenticator::class));
        $this->handler->setRequest(new HTTPRequest('GET', '/'));
        $this->handler->getRequest()->setSession(new Session([]));

        $this->member = $this->objFromFixture(Member::class, 'leslie_lawless');
        $this->method = $this->createMock(MethodInterface::class);
    }

    public function testOnRegisterMethod()
    {
        $this->handler->extend('onRegisterMethod', $this->member, $this->method);

        $message = $this->writer->getLastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('registered MFA method', $message);
        $this->assertStringContainsString('MethodInterface', $message, 'Method class name is in context');
    }

    public function testOnRegisterMethodFailure()
    {
        $this->handler->extend('onRegisterMethodFailure', $this->member, $this->method);

        $message = $this->writer->getLastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('failed registering new MFA method', $message);
        $this->assertStringContainsString('MethodInterface', $message, 'Method class name is in context');
    }

    public function testOnMethodVerificationFailure()
    {
        $this->member->config()->set('lock_out_after_incorrect_logins', 0);
        $this->handler->extend('onMethodVerificationFailure', $this->member, $this->method);

        $message = $this->writer->getLastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('failed to verify using MFA method', $message);
        $this->assertStringContainsString('MethodInterface', $message, 'Method class name is in context');
        $this->assertStringNotContainsString('attempt_limit', $message);
    }

    public function testOnMethodVerificationFailureWithLockoutConfiguration()
    {
        $this->member->config()->set('lock_out_after_incorrect_logins', 5);
        $this->member->registerFailedLogin();
        $this->member->registerFailedLogin();
        $this->member->registerFailedLogin();
        $this->handler->extend('onMethodVerificationFailure', $this->member, $this->method);

        $message = $this->writer->getLastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('failed to verify using MFA method', $message);
        $this->assertStringContainsString('MethodInterface', $message, 'Method class name is in context');
        // NB: json format is defined by AuditHookTest\Logger::log()
        $this->assertStringContainsString('"attempts":3', $message);
        $this->assertStringContainsString('"attempt_limit":5', $message);
    }

    public function testOnSkipRegistration()
    {
        $this->handler->extend('onSkipRegistration', $this->member, $this->method);

        $message = $this->writer->getLastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('skipped MFA registration', $message);
    }

    public function testOnMethodVerificationSuccess()
    {
        $this->handler->extend('onMethodVerificationSuccess', $this->member, $this->method);

        $message = $this->writer->getLastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('successfully verified using MFA method', $message);
        $this->assertStringContainsString('MethodInterface', $message, 'Method class name is in context');
    }
}
