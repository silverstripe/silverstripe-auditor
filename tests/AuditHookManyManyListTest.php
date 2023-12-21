<?php

namespace SilverStripe\Auditor\Tests;

use SilverStripe\Auditor\Tests\AuditHookTest\Logger;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;
use SilverStripe\Security\Group;
use SilverStripe\Security\Security;

class AuditHookManyManyListTest extends SapphireTest
{
    protected static $fixture_file = 'AuditHookMFATest.yml';

    protected Logger $writer;

    protected Member $member;

    protected Group $group;

    protected function setUp(): void
    {
        parent::setUp();

        $this->writer = new Logger;

        // Phase singleton out, so the message log is purged.
        Injector::inst()->unregisterNamedObject('AuditLogger');
        Injector::inst()->registerService($this->writer, 'AuditLogger');

        $this->member = $this->objFromFixture(Member::class, 'leslie_lawless');
        $this->group = $this->objFromFixture(Group::class, 'prisoners');
    }

    public function testRemoveByID(): void
    {
        $this->assertEquals(
            1,
            $this->group->Members()->filter('ID', $this->member->ID)->count(),
            'Leslie Lawless is part of the prisoners group'
        );

        $this->group->Members()->removeByID($this->member->ID);

        $message = $this->writer->getLastMessage();
        $currentUser = Security::getCurrentUser();
        $this->assertStringContainsString(
            sprintf(
                '"%s" (ID: %d) removed Member "%s" (ID: %d) from Group "%s" (ID: %d)',
                $currentUser->Email,
                $currentUser->ID,
                $this->member->Email,
                $this->member->ID,
                $this->group->Title,
                $this->group->ID,
            ),
            $message,
            'Log contains who removed Leslie Lawless from the prisoners group'
        );
    }
}
