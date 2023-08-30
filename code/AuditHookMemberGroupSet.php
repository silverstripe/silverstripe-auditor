<?php

namespace SilverStripe\Auditor;

use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\Member_GroupSet;
use SilverStripe\Security\Security;

class AuditHookMemberGroupSet extends Member_GroupSet
{
    /**
     * Overload {@link ManyManyList::removeByID()} so we can log
     * when a Member is removed from a Group.
     */
    public function removeByID($itemID)
    {
        parent::removeByID($itemID);

        if ($this->getJoinTable() === 'Group_Members') {
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

            $context = [
                'actor_email_or_title' => $currentMember->Email ?: $currentMember->Title,
                'actor_id' => $currentMember->ID,
                'member_email_or_title' => $member->Email ?: $member->Title,
                'member_id' => $member->ID,
                'group_title' => $group->Title,
                'group_id' => $group->ID,
                'type' => AuditedEventType::UPDATE,
            ];

            $this->getAuditLogger()->info(
                '"{actor_email_or_title}" (ID: {actor_id}) removed Member "{member_email_or_title}" (ID: {member_id}) from Group "{group_title}" (ID: {group_id})',
                $context,
            );
        }
    }

    protected function getAuditLogger()
    {
        // See note on AuditHook::getAuditLogger
        return Injector::inst()->get('AuditLogger');
    }
}
