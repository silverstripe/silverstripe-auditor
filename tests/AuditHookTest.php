<?php

namespace SilverStripe\Auditor\Tests;

use Page;
use SilverStripe\Auditor\Tests\AuditHookTest\Logger;
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
     * @var Logger
     */
    protected $writer = null;

    protected function setUp()
    {
        parent::setUp();

        $this->writer = new Logger;

        // Phase singleton out, so the message log is purged.
        Injector::inst()->unregisterNamedObject('AuditLogger');
        Injector::inst()->registerService($this->writer, 'AuditLogger');
    }

    public function testLoggingIn()
    {
        $this->logInWithPermission('ADMIN');

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('successfully logged in', $message);
    }

    public function testAutoLoggingIn()
    {
        // Simulate an autologin by calling the extension hook directly.
        // Member->autoLogin() relies on session and cookie state which we can't simulate here.
        $this->logInWithPermission('ADMIN');
        $member = Member::get()->filter(array('Email' => 'ADMIN@example.org'))->first();
        $member->extend('memberAutoLoggedIn');

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('successfully restored autologin', $message);
    }

    public function testLoggingOut()
    {
        $this->logInWithPermission('ADMIN');

        $member = Member::get()->filter(array('Email' => 'ADMIN@example.org'))->first();
        $this->logOut();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('successfully logged out', $message);
    }

    public function testLoggingWriteDoesNotOccurWhenNotLoggedIn()
    {
        $this->logOut();

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $message = $this->writer->getLastMessage();
        $this->assertEmpty($message, 'No one is logged in, so nothing was logged');
    }

    public function testLoggingWriteWhenLoggedIn()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('modified', $message);
        $this->assertContains(Group::class, $message);
    }

    public function testAddMemberToGroupUsingGroupMembersRelation()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $member = new Member(array('FirstName' => 'Joe', 'Email' => 'joe1'));
        $member->write();

        $group->Members()->add($member);

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('added Member "joe1"', $message);
        $this->assertContains('to Group "My group"', $message);
    }

    public function testAddMemberToGroupUsingMemberGroupsRelation()
    {
        $this->logInWithPermission('ADMIN');

        $group = new Group(array('Title' => 'My group'));
        $group->write();

        $member = new Member(array('FirstName' => 'Joe', 'Email' => 'joe2'));
        $member->write();

        $member->Groups()->add($group);

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('added Member "joe2"', $message);
        $this->assertContains('to Group "My group"', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('removed Member "joe3"', $message);
        $this->assertContains('from Group "My group"', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('removed Member "joe4"', $message);
        $this->assertContains('from Group "My group"', $message);
    }

    public function testAddRoleCodeToRole()
    {
        $this->logInWithPermission('ADMIN');

        $roleCode = new PermissionRoleCode(['Code' => 'grand_ruler']);
        $roleCode->write();

        $permissionRole = new PermissionRole(['Title' => 'Grand Ruler']);
        $permissionRole->Codes()->add($roleCode);
        $permissionRole->write();

        $message = $this->writer->getLastMessage();
        $this->assertContains('Effective code', $message);
        $this->assertContains('grand_ruler', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('Effective ViewerGroups', $message);
        $this->assertContains('OnlyTheseUsers', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('published Page', $message);
        $this->assertContains('My page', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('unpublished Page', $message);
        $this->assertContains('My page', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('duplicated Page', $message);
        $this->assertContains('My page', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('reverted Page', $message);
        $this->assertContains('My page', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('deleted Page', $message);
        $this->assertContains('My page', $message);
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

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('deleted Page', $message);
        $this->assertContains('My page', $message);
    }
}
