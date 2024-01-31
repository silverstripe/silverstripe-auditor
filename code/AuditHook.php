<?php

namespace SilverStripe\Auditor;

use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Email\Email;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\DataObjectSchema;
use SilverStripe\ORM\DB;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;
use SilverStripe\Security\PermissionRole;
use SilverStripe\Security\PermissionRoleCode;
use SilverStripe\Security\Security;

/**
 * Provides logging hooks that are inserted into Framework objects.
 *
 * @extends DataExtension<Member|SiteTree|Controller>
 */
class AuditHook extends DataExtension
{
    protected function getAuditLogger()
    {
        // We cannot use the 'dependencies' private property, because this will prevent us
        // from injecting a mock logger for testing. This is because by the time the testing framework
        // is instantiated, the part of the object graph where AuditLogger lives has already been created.
        // In other words, Framework does not permit hooking in early enough to adjust the graph when
        // 'dependencies' is used :-(
        return Injector::inst()->get('AuditLogger');
    }

    public static function handle_manipulation($manipulation)
    {
        $auditLogger = Injector::inst()->get('AuditLogger');

        $currentMember = Security::getCurrentUser();
        if (!($currentMember && $currentMember->exists())) {
            return false;
        }

        $schema = DataObject::getSchema();

        // The tables that we watch for manipulation on
        $watchedTables = [
            $schema->tableName(Member::class),
            $schema->tableName(Group::class),
            $schema->tableName(PermissionRole::class),
            $schema->tableName(PermissionRoleCode::class),
        ];

        foreach ($manipulation as $table => $details) {
            if (!in_array($details['command'], ['update', 'insert'])) {
                continue;
            }

            // logging writes to specific tables (just not when logging in, as it's noise)
            if (in_array($table, $watchedTables ?? [])
                && !preg_match('/Security/', @$_SERVER['REQUEST_URI'])
                && isset($details['id'])
            ) {
                $className = $schema->tableClass($table);

                $data = $className::get()->byID($details['id']);
                if (!$data) {
                    continue;
                }
                $actionText = 'modified '.$table;

                $extendedText = '';
                if ($table === $schema->tableName(Group::class)) {
                    $extendedText = sprintf(
                        'Effective permissions: %s',
                        implode(', ', $data->Permissions()->column('Code'))
                    );
                }
                if ($table === $schema->tableName(PermissionRole::class)) {
                    $extendedText = sprintf(
                        'Effective groups: %s, Effective permissions: %s',
                        implode(', ', $data->Groups()->column('Title')),
                        implode(', ', $data->Codes()->column('Code'))
                    );
                }
                if ($table === $schema->tableName(PermissionRoleCode::class)) {
                    $extendedText = sprintf(
                        'Effective code: %s',
                        $data->Code
                    );
                }
                if ($table === $schema->tableName(Member::class)) {
                    $extendedText = sprintf(
                        'Effective groups: %s',
                        implode(', ', $data->Groups()->column('Title'))
                    );
                }

                $auditLogger->info(sprintf(
                    '"%s" (ID: %s) %s (ID: %s, ClassName: %s, Title: "%s", %s)',
                    $currentMember->Email ?: $currentMember->Title,
                    $currentMember->ID,
                    $actionText,
                    $details['id'],
                    $data->ClassName,
                    $data->Title,
                    $extendedText
                ));
            }

            // log PermissionRole being added to a Group
            if ($table === $schema->tableName(Group::class) . '_Roles') {
                $role = PermissionRole::get()->byId($details['fields']['PermissionRoleID']);
                $group = Group::get()->byId($details['fields']['GroupID']);

                // if the permission role isn't already applied to the group
                if (!DB::query(sprintf(
                    'SELECT "ID" FROM "Group_Roles" WHERE "GroupID" = %s AND "PermissionRoleID" = %s',
                    $details['fields']['GroupID'],
                    $details['fields']['PermissionRoleID']
                ))->value()) {
                    $auditLogger->info(sprintf(
                        '"%s" (ID: %s) added PermissionRole "%s" (ID: %s) to Group "%s" (ID: %s)',
                        $currentMember->Email ?: $currentMember->Title,
                        $currentMember->ID,
                        $role->Title,
                        $role->ID,
                        $group->Title,
                        $group->ID
                    ));
                }
            }

            // log Member added to a Group
            if ($table === $schema->tableName(Group::class) . '_Members') {
                $member = Member::get()->byId($details['fields']['MemberID']);
                $group = Group::get()->byId($details['fields']['GroupID']);

                // if the user isn't already in the group, log they've been added
                if (!DB::query(sprintf(
                    'SELECT "ID" FROM "Group_Members" WHERE "GroupID" = %s AND "MemberID" = %s',
                    $details['fields']['GroupID'],
                    $details['fields']['MemberID']
                ))->value()) {
                    $auditLogger->info(sprintf(
                        '"%s" (ID: %s) added Member "%s" (ID: %s) to Group "%s" (ID: %s)',
                        $currentMember->Email ?: $currentMember->Title,
                        $currentMember->ID,
                        $member->Email ?: $member->Title,
                        $member->ID,
                        $group->Title,
                        $group->ID
                    ));
                }
            }
        }
    }

    /**
     * Log a record being published.
     */
    public function onAfterPublish(&$original)
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $effectiveViewerGroups = '';
        if ($this->owner->CanViewType === 'OnlyTheseUsers') {
            $originalViewerGroups = $original ? $original->ViewerGroups()->column('Title') : [];
            $effectiveViewerGroups = implode(', ', $originalViewerGroups);
        }
        if (!$effectiveViewerGroups) {
            $effectiveViewerGroups = $this->owner->CanViewType;
        }

        $effectiveEditorGroups = '';
        if ($this->owner->CanEditType === 'OnlyTheseUsers') {
            $originalEditorGroups =  $original ? $original->EditorGroups()->column('Title') : [];
            $effectiveEditorGroups = implode(', ', $originalEditorGroups);
        }
        if (!$effectiveEditorGroups) {
            $effectiveEditorGroups = $this->owner->CanEditType;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) published %s "%s" (ID: %s, Version: %s, ClassName: %s, Effective ViewerGroups: %s, '
            . 'Effective EditorGroups: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID,
            $this->owner->Version,
            $this->owner->ClassName,
            $effectiveViewerGroups,
            $effectiveEditorGroups
        ));
    }

    /**
     * Log a record being unpublished.
     */
    public function onAfterUnpublish()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) unpublished %s "%s" (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        ));
    }

    /**
     * Log a record being reverted to live.
     */
    public function onAfterRevertToLive()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) reverted %s "%s" (ID: %s) to it\'s live version (#%d)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID,
            $this->owner->Version
        ));
    }

    /**
     * Log a record being duplicated.
     */
    public function onAfterDuplicate()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) duplicated %s "%s" (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        ));
    }

    /**
     * Log a record being deleted.
     */
    public function onAfterDelete()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) deleted %s "%s" (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        ));
    }

    /**
     * Log a record being restored to stage.
     */
    public function onAfterRestoreToStage()
    {
        $member = Security::getCurrentUser();
        if (!$member || !$member->exists()) {
            return false;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) restored %s "%s" to stage (ID: %s)',
            $member->Email ?: $member->Title,
            $member->ID,
            $this->owner->singular_name(),
            $this->owner->Title,
            $this->owner->ID
        ));
    }

    /**
     * Log successful login attempts.
     */
    public function afterMemberLoggedIn()
    {
        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) successfully logged in',
            $this->owner->Email ?: $this->owner->Title,
            $this->owner->ID
        ));
    }

    /**
     * Log successfully restored sessions from "remember me" cookies ("auto login").
     */
    public function memberAutoLoggedIn()
    {
        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) successfully restored autologin session',
            $this->owner->Email ?: $this->owner->Title,
            $this->owner->ID
        ));
    }

    /**
     * Log failed login attempts.
     */
    public function authenticationFailed($data)
    {
        // LDAP authentication uses a "Login" POST field instead of Email.
        $login = isset($data['Login'])
            ? $data['Login']
            : (isset($data['Email']) ? $data['Email'] : '');

        if (empty($login)) {
            return $this->getAuditLogger()->warning(
                'Could not determine username/email of failed authentication. '.
                'This could be due to login form not using Email or Login field for POST data.'
            );
        }

        $this->getAuditLogger()->info(sprintf('Failed login attempt using email "%s"', $login));
    }

    /**
     * Log failed login attempts when the email address doesn't map to an existing member record
     */
    public function authenticationFailedUnknownUser($data)
    {
        $this->authenticationFailed($data);
    }

    /**
     * Log permission failures (where the status is set after init of page).
     */
    public function onAfterInit()
    {
        // Suppress errors if dev/build necessary
        if (!Security::database_is_ready()) {
            return false;
        }
        $currentMember = Security::getCurrentUser();
        if (!$currentMember || !$currentMember->exists()) {
            return false;
        }

        $statusCode = $this->owner->getResponse()->getStatusCode();

        if (substr($statusCode ?? '', 0, 1) == '4') {
            $this->logPermissionDenied($statusCode, $currentMember);
        }
    }

    protected function logPermissionDenied($statusCode, $member)
    {
        $this->getAuditLogger()->info(sprintf(
            'HTTP code %s - "%s" (ID: %s) is denied access to %s',
            $statusCode,
            $member->Email ?: $member->Title,
            $member->ID,
            $_SERVER['REQUEST_URI']
        ));
    }

    /**
     * Log successful logout.
     */
    public function afterMemberLoggedOut()
    {
        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) successfully logged out',
            $this->owner->Email ?: $this->owner->Title,
            $this->owner->ID
        ));
    }
}
