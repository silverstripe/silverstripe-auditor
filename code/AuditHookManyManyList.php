<?php

namespace SilverStripe\Auditor;

use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class AuditHookManyManyList extends ManyManyList
{
    /**
     * Overload {@link ManyManyList::removeByID()} so we can log
     * when a Member is removed from a Group.
     */
    public function removeByID($itemID)
    {
        parent::removeByID($itemID);

        if ($this->getJoinTable() == 'Group_Members') {
            $currentMember = Security::getCurrentUser();
            if (!($currentMember && $currentMember->exists())) {
                return;
            }

            $member = Member::get()->byId($this->getForeignID());
            $group = Group::get()->byId($itemID);

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
