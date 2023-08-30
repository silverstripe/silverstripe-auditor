<?php

namespace SilverStripe\Auditor\Tests;

use Monolog\Logger;
use Monolog\LogRecord;
use Monolog\Processor\PsrLogMessageProcessor;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use PHPUnit\Framework\MockObject\MockObject;
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
     * @var TestHandler
     */
    protected $testHandler;

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

    private function lastRecord(): LogRecord|false
    {
        $records = $this->testHandler->getRecords();
        return end($records);

    }

    private function lastMessage()
    {
        return $this->lastRecord()->message ?? '';
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (!interface_exists(MethodInterface::class)) {
            $this->markTestSkipped('This test requires the silverstripe/mfa module to be installed');
            return;
        }

        $this->testHandler = new TestHandler;
        $logger = (new Logger('AuditTesting'))
            ->pushHandler($this->testHandler)
            ->pushProcessor(new PsrLogMessageProcessor);

        // Phase singleton out, so the message log is purged.
        Injector::inst()->unregisterNamedObject('AuditLogger');
        Injector::inst()->registerService($logger, 'AuditLogger');

        $this->handler = new LoginHandler('foo', $this->createMock(MemberAuthenticator::class));
        $this->handler->setRequest(new HTTPRequest('GET', '/'));
        $this->handler->getRequest()->setSession(new Session([]));

        $this->member = $this->objFromFixture(Member::class, 'leslie_lawless');
        $this->method = $this->createMock(MethodInterface::class);
    }

    public function testOnRegisterMethod()
    {
        $this->handler->extend('onRegisterMethod', $this->member, $this->method);

        $message = $this->lastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('registered MFA method', $message);

        $context = $this->lastRecord()->context;
        $this->assertArrayHasKey('method', $context, 'Method class name is in context');
        $this->assertStringContainsString('MethodInterface', $context['method'], 'Method class is correct');
    }

    public function testOnRegisterMethodFailure()
    {
        $this->handler->extend('onRegisterMethodFailure', $this->member, $this->method);

        $message = $this->lastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('failed registering new MFA method', $message);

        $context = $this->lastRecord()->context;
        $this->assertArrayHasKey('method', $context, 'Method class name is in context');
        $this->assertStringContainsString('MethodInterface', $context['method'], 'Method class is correct');
    }

    public function testOnMethodVerificationFailure()
    {
        $this->member->config()->set('lock_out_after_incorrect_logins', 0);
        $this->handler->extend('onMethodVerificationFailure', $this->member, $this->method);

        $message = $this->lastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('failed to verify using MFA method', $message);

        $context = $this->lastRecord()->context;
        $this->assertArrayHasKey('method', $context, 'Method class name is in context');
        $this->assertStringContainsString('MethodInterface', $context['method'], 'Method class is correct');

        $this->assertStringNotContainsString('attempt_limit', $message);
    }

    public function testOnMethodVerificationFailureWithLockoutConfiguration()
    {
        $this->member->config()->set('lock_out_after_incorrect_logins', 5);
        $this->member->registerFailedLogin();
        $this->member->registerFailedLogin();
        $this->member->registerFailedLogin();
        $this->handler->extend('onMethodVerificationFailure', $this->member, $this->method);

        $message = $this->lastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('failed to verify using MFA method', $message);

        $context = $this->lastRecord()->context;
        $this->assertArrayHasKey('method', $context, 'Method class name is in context');
        $this->assertStringContainsString('MethodInterface', $context['method'], 'Method class is correct');

        $this->assertArrayHasKey('attempts', $context, 'Attempts is in context');
        $this->assertEquals(3, $context['attempts'], 'Correct number of attempts are logged');
        $this->assertArrayHasKey('attempt_limit', $context, 'Attempt limit is in context');
        $this->assertEquals(5, $context['attempt_limit'], 'Correct attempt limit is logged');
    }

    public function testOnSkipRegistration()
    {
        $this->handler->extend('onSkipRegistration', $this->member, $this->method);

        $message = $this->lastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('skipped MFA registration', $message);
    }

    public function testOnMethodVerificationSuccess()
    {
        $this->handler->extend('onMethodVerificationSuccess', $this->member, $this->method);

        $message = $this->lastMessage();
        $this->assertStringContainsString('leslie@example.com', $message);
        $this->assertStringContainsString('successfully verified using MFA method', $message);

        $context = $this->lastRecord()->context;
        $this->assertArrayHasKey('method', $context, 'Method class name is in context');
        $this->assertStringContainsString('MethodInterface', $context['method'], 'Method class is correct');
    }
}
