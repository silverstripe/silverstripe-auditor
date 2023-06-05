<?php

namespace SilverStripe\Auditor\Tests;

use Monolog\Logger;
use Monolog\Handler\TestHandler;
use Monolog\Processor\PsrLogMessageProcessor;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\Security\SecurityToken;
use SilverStripe\SessionManager\Controllers\LoginSessionController;
use SilverStripe\SessionManager\Models\LoginSession;

class AuditHookSessionManagerTest extends SapphireTest
{
    protected $usesDatabase = true;

    /**
     * @var TestHandler
     */
    protected $handler = null;

    private function lastMessage(): string
    {
        $records = $this->handler->getRecords();
        /** @var LogRecord $lastRecord */
        $lastRecord = end($records);
        return $lastRecord->message;
    }

    protected function setUp(): void
    {
        parent::setUp();
        if (!class_exists(LoginSessionController::class)) {
            $this->markTestSkipped('This test requires the silverstripe/session-manager module to be installed');
            return;
        }

        $this->handler = new TestHandler;
        $logger = (new Logger('AuditTesting'))
            ->pushHandler($this->handler)
            ->pushProcessor(new PsrLogMessageProcessor);

        Injector::inst()->unregisterNamedObject('AuditLogger');
        Injector::inst()->registerService($logger, 'AuditLogger');
    }

    public function testOnBeforeRemoveLoginSession()
    {
        $this->logInWithPermission('ADMIN');

        $currentUser = Security::getCurrentUser();

        $member = new Member(array('FirstName' => 'Joe', 'Email' => 'joe3'));
        $member->write();
        $request = Controller::curr()->getRequest();
        $loginSession = LoginSession::generate($member, false, $request);

        SecurityToken::disable();
        $mockRequest = new HTTPRequest('DELETE', '');
        $mockRequest->setRouteParams(['ID' => $loginSession->ID]);
        $controller = new LoginSessionController();
        $controller->remove($mockRequest);

        $lastMessage = $this->lastMessage();

        $message = sprintf(
            'Login session (ID: %s) for Member "%s" (ID: %s) is being removed by Member "%s" (ID: %s)',
            $loginSession->ID,
            $member->Email,
            $member->ID,
            $currentUser->Email,
            $currentUser->ID
        );
        $this->assertStringContainsString($message, $lastMessage);
    }
}
