<?php

namespace SilverStripe\Auditor\Tests;

use Page;
use Monolog\Logger;
use Monolog\Handler\TestHandler;
use Monolog\LogRecord;
use Monolog\Processor\PsrLogMessageProcessor;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\PermissionRole;
use SilverStripe\Security\PermissionRoleCode;

class AuditHookTest extends FunctionalTest
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

        $this->handler = new TestHandler;
        $logger = (new Logger('AuditTesting'))
            ->pushHandler($this->handler)
            ->pushProcessor(new PsrLogMessageProcessor);

        // Phase singleton out, so the message log is purged.
        Injector::inst()->unregisterNamedObject('AuditLogger');
        Injector::inst()->registerService($logger, 'AuditLogger');
    }

    public function testLoggingIn()
    {
        $this->logInWithPermission('ADMIN');

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('successfully logged in', $message);
    }

    public function testAutoLoggingIn()
    {
        // Simulate an autologin by calling the extension hook directly.
        // Member->autoLogin() relies on session and cookie state which we can't simulate here.
        $this->logInWithPermission('ADMIN');
        $member = Member::get()->filter(array('Email' => 'ADMIN@example.org'))->first();
        $member->extend('memberAutoLoggedIn');

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('successfully restored autologin', $message);
    }

    public function testLoggingOut()
    {
        $this->logInWithPermission('ADMIN');

        $member = Member::get()->filter(array('Email' => 'ADMIN@example.org'))->first();
        $this->logOut();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('successfully logged out', $message);
    }

    public function testLoggingWriteDoesNotOccurWhenNotLoggedIn()
    {
        $this->logOut();

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $this->assertEmpty($this->handler->getRecords(), 'No one is logged in, so nothing was logged');
    }

    public function testLoggingWriteWhenLoggedIn()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('modified', $message);
        $this->assertStringContainsString(Group::class, $message);
    }

    public function testAddMemberToGroupUsingGroupMembersRelation()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $member = new Member(array('FirstName' => 'Joe', 'Email' => 'joe1'));
        $member->write();

        $group->Members()->add($member);

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('added Member "joe1"', $message);
        $this->assertStringContainsString('to Group "My group"', $message);
    }

    public function testAddMemberToGroupUsingMemberGroupsRelation()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $member = new Member(array('FirstName' => 'Joe', 'Email' => 'joe2'));
        $member->write();

        $member->Groups()->add($group);

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('added Member "joe2"', $message);
        $this->assertStringContainsString('to Group "My group"', $message);
    }

    public function testRemoveMemberFromGroupUsingGroupMembersRelation()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $member = new Member(array('FirstName' => 'Joe', 'Email' => 'joe3'));
        $member->write();

        $group->Members()->add($member);
        $group->Members()->remove($member);

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('removed Member "joe3"', $message);
        $this->assertStringContainsString('from Group "My group"', $message);
    }

    public function testRemoveMemberFromGroupUsingMemberGroupsRelation()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $member = new Member(array('FirstName' => 'Joe', 'Email' => 'joe4'));
        $member->write();

        $member->Groups()->add($group);
        $member->Groups()->remove($group);

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('removed Member "joe4"', $message);
        $this->assertStringContainsString('from Group "My group"', $message);
    }

    public function testAddRoleCodeToRole()
    {
        $this->logInWithPermission('ADMIN');

        $roleCode = new PermissionRoleCode(['Code' => 'grand_ruler']);
        $roleCode->write();

        $permissionRole = new PermissionRole(['Title' => 'Grand Ruler']);
        $permissionRole->Codes()->add($roleCode);
        $permissionRole->write();

        $message = $this->lastMessage();
        $this->assertStringContainsString('Effective code', $message);
        $this->assertStringContainsString('grand_ruler', $message);
    }

    public function testAddViewerGroupToPage()
    {
        if (!class_exists(Page::class)) {
            $this->markTestSkipped('This test requires the CMS module installed.');
        }

        $this->logInWithPermission('ADMIN');

        $group = new Group();
        $group->Title = 'Test group';
        $group->write();

        $page = new Page();
        $page->CanViewType = 'OnlyTheseUsers';
        $page->ViewerGroups()->add($group);
        $page->write();
        $page->publishSingle();

        $message = $this->lastMessage();
        $this->assertStringContainsString('Effective ViewerGroups', $message);
        $this->assertStringContainsString('OnlyTheseUsers', $message);
    }

    public function testPublishPage()
    {
        if (!class_exists(Page::class)) {
            $this->markTestSkipped('This test requires the CMS module installed.');
        }

        $this->logInWithPermission('ADMIN');

        $page = new Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->write();
        $page->publishSingle();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('published Page', $message);
        $this->assertStringContainsString('My page', $message);
    }

    public function testUnpublishPage()
    {
        if (!class_exists(Page::class)) {
            $this->markTestSkipped('This test requires the CMS module installed.');
        }

        $this->logInWithPermission('ADMIN');

        $page = new Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->write();
        $page->publishSingle();
        $page->doUnpublish();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('unpublished Page', $message);
        $this->assertStringContainsString('My page', $message);
    }

    public function testDuplicatePage()
    {
        if (!class_exists(Page::class)) {
            $this->markTestSkipped('This test requires the CMS module installed.');
        }

        $this->logInWithPermission('ADMIN');

        $page = new Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->write();
        $page->duplicate();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('duplicated Page', $message);
        $this->assertStringContainsString('My page', $message);
    }

    public function testRevertToLive()
    {
        if (!class_exists(Page::class)) {
            $this->markTestSkipped('This test requires the CMS module installed.');
        }

        $this->logInWithPermission('ADMIN');

        $page = new Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->write();
        $page->publishSingle();

        $page->Content = 'Changed';
        $page->write();
        $page->doRevertToLive();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('reverted Page', $message);
        $this->assertStringContainsString('My page', $message);
    }

    public function testDelete()
    {
        if (!class_exists(Page::class)) {
            $this->markTestSkipped('This test requires the CMS module installed.');
        }

        $this->logInWithPermission('ADMIN');

        $page = new Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->write();
        $page->publishSingle();

        $page->delete();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('deleted Page', $message);
        $this->assertStringContainsString('My page', $message);
    }

    public function testRestoreToStage()
    {
        if (!class_exists(Page::class)) {
            $this->markTestSkipped('This test requires the CMS module installed.');
        }

        $this->logInWithPermission('ADMIN');

        $page = new Page();
        $page->Title = 'My page';
        $page->Content = 'Published';
        $page->write();
        $page->publishSingle();

        $page->Content = 'This is my page content';
        $page->write();
        $page->publishSingle();
        $page->delete();

        $message = $this->lastMessage();
        $this->assertStringContainsString('ADMIN@example.org', $message);
        $this->assertStringContainsString('deleted Page', $message);
        $this->assertStringContainsString('My page', $message);
    }
}
