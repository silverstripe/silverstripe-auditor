<?php

namespace SilverStripe\Auditor;

use Psr\Log\LoggerInterface;
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
 */
class AuditHook extends DataExtension
{
    /**
     * @return LoggerInterface
     */
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
        /** @var LoggerInterface $auditLogger */
        $auditLogger = Injector::inst()->get('AuditLogger');

        $currentMember = Security::getCurrentUser();
        if (!($currentMember && $currentMember->exists())) {
            return false;
        }

        /** @var DataObjectSchema $schema */
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

                /** @var DataObject $data */
                $data = $className::get()->byID($details['id']);
                if (!$data) {
                    continue;
                }
                $actionText = 'modified '.$table;

                $extendedText = '';
                if ($table === $schema->tableName(Group::class)) {
                    /** @var Group $data */
                    $extendedText = sprintf(
                        'Effective permissions: %s',
                        implode(', ', $data->Permissions()->column('Code'))
                    );
                }
                if ($table === $schema->tableName(PermissionRole::class)) {
                    /** @var PermissionRole $data */
                    $extendedText = sprintf(
                        'Effective groups: %s, Effective permissions: %s',
                        implode(', ', $data->Groups()->column('Title')),
                        implode(', ', $data->Codes()->column('Code'))
                    );
                }
                if ($table === $schema->tableName(PermissionRoleCode::class)) {
                    /** @var PermissionRoleCode $data */
                    $extendedText = sprintf(
                        'Effective code: %s',
                        $data->Code
                    );
                }
                if ($table === $schema->tableName(Member::class)) {
                    /** @var Member $data */
                    $extendedText = sprintf(
                        'Effective groups: %s',
                        implode(', ', $data->Groups()->column('Title'))
                    );
                }

                $crud = AuditedEventType::CREATE;
                if ($details['command'] === 'update') {
                    $crud = AuditedEventType::UPDATE;
                } elseif ($details['command'] === 'insert') {
                    $crud = AuditedEventType::CREATE;
                }

                $auditLogger->info(
                    '"{actor_email_or_title}" (ID: {actor_id}) {action} (ID: {object_id}, ClassName: {object_class}, Title: "{object_title}", {extended_text})',
                    [
                        'actor_email_or_title' => $currentMember->Email ?: $currentMember->Title,
                        'actor_id' => $currentMember->ID,
                        'action' => $actionText,
                        'object_id' => $details['id'],
                        'object_class' => $data->getClassName(),
                        'object_title' => $data->Title,
                        'extended_text' => $extendedText,
                        'type' => $crud,
                    ]
                );
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
                    $auditLogger->info(
                        '"{actor_email_or_title}" (ID: {actor_id}) added PermissionRole "{permission_role_title}" (ID: {permission_role_id}) to Group "{group_title}" (ID: {group_id})',
                        [
                            'actor_email_or_title' => $currentMember->Email ?: $currentMember->Title,
                            'actor_id' => $currentMember->ID,
                            'permission_role_title' => $role->Title,
                            'permission_role_id' => $role->ID,
                            'group_title' => $group->Title,
                            'group_id' => $group->ID,
                            'type' => AuditedEventType::UPDATE,
                        ]
                    );
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
                    $auditLogger->info(
                        '"{actor_email_or_title}" (ID: {actor_id}) added Member "{member_email_or_title}" (ID: {member_id}) to Group "{group_title}" (ID: {group_id})',
                        [
                            'actor_email_or_title' => $currentMember->Email ?: $currentMember->Title,
                            'actor_id' => $currentMember->ID,
                            'member_email_or_title' => $member->Email ?: $member->Title,
                            'member_id' => $member->ID,
                            'group_title' => $group->Title,
                            'group_id' => $group->ID,
                            'type' => AuditedEventType::UPDATE,
                        ]
                    );
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

        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'object_singular_name' => $this->owner->singular_name(),
            'object_title' => $this->owner->Title,
            'object_id' => $this->owner->ID,
            'object_version' => $this->owner->Version,
            'object_class' => $this->owner->getClassName(),
            'effective_viewer_groups' => '',
            'effective_editor_groups' => '',
            'type' => AuditedEventType::CREATE,
        ];

        if ($this->owner->CanViewType === 'OnlyTheseUsers') {
            $originalViewerGroups = $original ? $original->ViewerGroups()->column('Title') : [];
            $context['effective_viewer_groups'] = implode(', ', $originalViewerGroups);
        }
        if (!$context['effective_viewer_groups']) {
            $context['effective_viewer_groups'] = $this->owner->CanViewType;
        }

        if ($this->owner->CanEditType === 'OnlyTheseUsers') {
            $originalEditorGroups =  $original ? $original->EditorGroups()->column('Title') : [];
            $context['effective_editor_groups'] = implode(', ', $originalEditorGroups);
        }
        if (!$context['effective_editor_groups']) {
            $context['effective_editor_groups'] = $this->owner->CanEditType;
        }

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) published {object_singular_name} "{object_title}" (ID: {object_id}, Version: {object_version}, ClassName: {object_class}, Effective ViewerGroups: {effective_viewer_groups}, '
                . 'Effective EditorGroups: {effective_editor_groups})',
            $context
        );
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

        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'object_singular_name' => $this->owner->singular_name(),
            'object_title' => $this->owner->Title,
            'object_id' => $this->owner->ID,
            'type' => AuditedEventType::DELETE
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) unpublished {object_singular_name} "{object_title}" (ID: {object_id})',
            $context,
        );
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

        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'object_singular_name' => $this->owner->singular_name(),
            'object_title' => $this->owner->Title,
            'object_id' => $this->owner->ID,
            'object_version' => $this->owner->Version,
            'type' => AuditedEventType::UPDATE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) reverted {object_singular_name} "{object_title}" (ID: {object_id}) to it\'s live version (#{object_version})',
            $context,
        );
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

        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'object_singular_name' => $this->owner->singular_name(),
            'object_title' => $this->owner->Title,
            'object_id' => $this->owner->ID,
            'type' => AuditedEventType::CREATE
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) duplicated {object_singular_name} "{object_title}" (ID: {object_id})',
            $context,
        );
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

        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'object_singular_name' => $this->owner->singular_name(),
            'object_title' => $this->owner->Title,
            'object_id' => $this->owner->ID,
            'type' => AuditedEventType::DELETE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) deleted {object_singular_name} "{object_title}" (ID: {object_id})',
            $context,
        );
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

        $context = [
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'object_singular_name' => $this->owner->singular_name(),
            'object_title' => $this->owner->Title,
            'object_id' => $this->owner->ID,
            'type' => AuditedEventType::CREATE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) restored {object_singular_name} "{object_title}" to stage (ID: {object_id})',
            $context,
        );
    }

    /**
     * Log successful login attempts.
     */
    public function afterMemberLoggedIn()
    {
        $context = [
            'actor_email_or_title' => $this->owner->Email ?: $this->owner->Title,
            'actor_id' => $this->owner->ID,
            'type' => AuditedEventType::NOTICE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) successfully logged in',
            $context,
        );
    }

    /**
     * Log successfully restored sessions from "remember me" cookies ("auto login").
     */
    public function memberAutoLoggedIn()
    {
        $context = [
            'actor_email_or_title' => $this->owner->Email ?: $this->owner->Title,
            'actor_id' => $this->owner->ID,
            'type' => AuditedEventType::NOTICE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) successfully restored autologin session',
            $context,
        );
    }

    /**
     * Log failed login attempts.
     */
    public function authenticationFailed($data)
    {
        $context = [
            'type' => AuditedEventType::NOTICE,
        ];

        // LDAP authentication uses a "Login" POST field instead of Email.
        $login = isset($data['Login'])
            ? $data['Login']
            : (isset($data[Email::class]) ? $data[Email::class] : '');

        if (empty($login)) {
            return $this->getAuditLogger()->warning(
                'Could not determine username/email of failed authentication. ' .
                    'This could be due to login form not using Email or Login field for POST data.'
            );
        }

        $context['email'] = $login;

        $this->getAuditLogger()->info('Failed login attempt using email "{email}"', $context);
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
        $context = [
            'status_code' => $statusCode,
            'actor_email_or_title' => $member->Email ?: $member->Title,
            'actor_id' => $member->ID,
            'request_uri' => $_SERVER['REQUEST_URI'],
            'type' => AuditedEventType::NOTICE,
        ];

        $this->getAuditLogger()->info(
            'HTTP code {status_code} - "{actor_email_or_title}" (ID: {actor_id}) is denied access to {request_uri}',
            $context,
        );
    }

    /**
     * Log successful logout.
     */
    public function afterMemberLoggedOut()
    {
        $context = [
            'actor_email_or_title' => $this->owner->Email ?: $this->owner->Title,
            'actor_id' => $this->owner->ID,
            'type' => AuditedEventType::NOTICE,
        ];

        $this->getAuditLogger()->info(
            '"{actor_email_or_title}" (ID: {actor_id}) successfully logged out',
            $context,
        );
    }
}
