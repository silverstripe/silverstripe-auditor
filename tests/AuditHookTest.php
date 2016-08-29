<?php

namespace SilverStripe\Auditor\Tests;

class AuditHookTest extends \FunctionalTest
{

    protected $usesDatabase = true;

    protected $writer = null;

    public function setUp()
    {
        parent::setUp();

        $this->writer = new AuditLoggerTest_Logger;
		// Phase singleton out, so the message log is purged.
		\Injector::inst()->unregisterNamedObject('AuditLogger');
		\Injector::inst()->registerService($this->writer, 'AuditLogger');

        // ensure the manipulations are being captured, normally called in {@link AuditLogger::onBeforeInit()}
        // but tests will reset this during setting up, so we need to set it back again.
        \Silverstripe\Auditor\AuditHook::bind_manipulation_capture();
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
        $member = \Member::get()->filter(array('Email' => 'ADMIN@example.org'))->first();
        $member->extend('memberAutoLoggedIn');

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('successfully restored autologin', $message);
    }

    public function testLoggingOut()
    {
        $this->logInWithPermission('ADMIN');

        $member = \Member::get()->filter(array('Email' => 'ADMIN@example.org'))->first();
        $member->logOut();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('successfully logged out', $message);
    }

    public function testLoggingWriteDoesNotOccurWhenNotLoggedIn()
    {
        $this->session()->inst_set('loggedInAs', null);

        $group = new \Group(array('Title' => 'My group'));
        $group->write();

        $message = $this->writer->getLastMessage();
        $this->assertEmpty($message, 'No one is logged in, so nothing was logged');
    }

    public function testLoggingWriteWhenLoggedIn()
    {
        $this->logInWithPermission('ADMIN');

        $group = new \Group(array('Title' => 'My group'));
        $group->write();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('modified', $message);
        $this->assertContains('Group', $message);
    }

    public function testAddMemberToGroupUsingGroupMembersRelation()
    {
        $this->logInWithPermission('ADMIN');

        $group = new \Group(array('Title' => 'My group'));
        $group->write();

        $member = new \Member(array('FirstName' => 'Joe', 'Email' => 'joe1'));
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

        $group = new \Group(array('Title' => 'My group'));
        $group->write();

        $member = new \Member(array('FirstName' => 'Joe', 'Email' => 'joe2'));
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

        $group = new \Group(array('Title' => 'My group'));
        $group->write();

        $member = new \Member(array('FirstName' => 'Joe', 'Email' => 'joe3'));
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

        $group = new \Group(array('Title' => 'My group'));
        $group->write();

        $member = new \Member(array('FirstName' => 'Joe', 'Email' => 'joe4'));
        $member->write();

        $member->Groups()->add($group);
        $member->Groups()->remove($group);

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('removed Member "joe4"', $message);
        $this->assertContains('from Group "My group"', $message);
    }

    public function testPublishPage()
    {
        $this->logInWithPermission('ADMIN');

        $page = new \Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->doPublish();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('published Page', $message);
        $this->assertContains('My page', $message);
    }

    public function testUnpublishPage()
    {
        $this->logInWithPermission('ADMIN');

        $page = new \Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->doPublish();
        $page->doUnpublish();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('unpublished Page', $message);
        $this->assertContains('My page', $message);
    }

    public function testDuplicatePage()
    {
        $this->logInWithPermission('ADMIN');

        $page = new \Page();
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
        $this->logInWithPermission('ADMIN');

        $page = new \Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->doPublish();

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
        $this->logInWithPermission('ADMIN');

        $page = new \Page();
        $page->Title = 'My page';
        $page->Content = 'This is my page content';
        $page->doPublish();

        $page->delete();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('deleted Page', $message);
        $this->assertContains('My page', $message);
    }

    public function testRestoreToStage()
    {
        $this->logInWithPermission('ADMIN');

        $page = new \Page();
        $page->Title = 'My page';
        $page->Content = 'Published';
        $page->doPublish();

        $page->Content = 'This is my page content';
        $page->doPublish();
        $page->delete();

        $message = $this->writer->getLastMessage();
        $this->assertContains('ADMIN@example.org', $message);
        $this->assertContains('deleted Page', $message);
        $this->assertContains('My page', $message);
    }

    public function tearDown()
    {
        parent::tearDown();

        \SS_Log::remove_writer($this->writer);
        unset($this->writer);
    }
}

class AuditLoggerTest_Logger extends \Psr\Log\AbstractLogger
{
    protected $messages = array();

	public function log($level, $message, array $context = array())
    {
        array_push($this->messages, $message);
	}

    public function getLastMessage()
    {
        return end($this->messages);
    }

    public function getMessages()
    {
        return $this->messages;
    }
}
