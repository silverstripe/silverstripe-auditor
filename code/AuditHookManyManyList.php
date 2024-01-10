<?php

namespace SilverStripe\Auditor;

use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * AuditHookManyManyList is meant to override ManyManyList. When a Member is
 * removed from a Group, it logs the event.
 *
 * @template T of DataObject
 * @extends ManyManyList<T>
 */
class AuditHookManyManyList extends ManyManyList
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
            if (!($currentMember && $currentMember->exists())) {
                return;
            }

            $member = Member::get()->byId($itemID);
            $group = Group::get()->byId($this->getForeignID());

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
