<?php

namespace SilverStripe\Auditor;

use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\Member_GroupSet;
use SilverStripe\Security\Security;

/**
 * AuditHookMemberGroupSet is meant to override Member_GroupSet. When a Group
 * is removed from a Member, it logs the event.
 */
class AuditHookMemberGroupSet extends Member_GroupSet
{
    /**
     * Overload {@link ManyManyList::removeByID()} so we can log
     * when a Member is removed from a Group.
     */
    public function removeByID($itemID)
    {
        parent::removeByID($itemID);

        $memberGroupJoinTable = Member::singleton()->Groups()->getJoinTable();

        if ($this->getJoinTable() === $memberGroupJoinTable) {
            $currentMember = Security::getCurrentUser();
            if (!$currentMember || !$currentMember->exists()) {
                return;
            }

            $group = Group::get()->byId($itemID);
            $member = Member::get()->byId($this->getForeignID());

            if (!$group) {
                return;
            }
            if (!$member) {
                return;
            }

            $this->getAuditLogger()->info(sprintf(
                '"%s" (ID: %s) removed Member "%s" (ID: %s) from Group "%s" (ID: %s)',
                $currentMember->Email ?: $currentMember->Title,
                $currentMember->ID,
                $member->Email ?: $member->Title,
                $member->ID,
                $group->Title,
                $group->ID
            ));
        }
    }

    protected function getAuditLogger()
    {
        // See note on AuditHook::getAuditLogger
        return Injector::inst()->get('AuditLogger');
    }
}
