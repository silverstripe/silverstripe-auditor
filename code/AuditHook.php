<?php

namespace SilverStripe\Auditor;

/**
 * Provides logging hooks that are inserted into Framework objects.
 */
class AuditHook extends \SiteTreeExtension
{

	protected function getAuditLogger() {
		// We cannot use the 'dependencies' private property, because this will prevent us
		// from injecting a mock logger for testing. This is because by the time the testing framework
		// is instantiated, the part of the object graph where AuditLogger lives has already been created.
		// In other words, Framework does not permit hooking in early enough to adjust the graph when
		// 'dependencies' is used :-(
		return \Injector::inst()->get('AuditLogger');
	}

    /**
     * This will bind a new class dynamically so we can hook into manipulation
     * and capture it. It creates a new PHP file in the temp folder, then
     * loads it and sets it as the active DB class.
     */
    public static function bind_manipulation_capture()
    {
        global $databaseConfig;

        $current = \DB::getConn();
        if (!$current || !$current->currentDatabase() || @$current->isManipulationLoggingCapture) {
            return;
        } // If not yet set, or its already captured, just return

        $type = get_class($current);
        $file = TEMP_FOLDER."/.cache.CLC.$type";
        $dbClass = 'AuditLoggerManipulateCapture_'.$type;

        if (!is_file($file)) {
            file_put_contents($file, "<?php
				class $dbClass extends $type {
					public \$isManipulationLoggingCapture = true;

					public function manipulate(\$manipulation) {
						\SilverStripe\Auditor\AuditHook::handle_manipulation(\$manipulation);
						return parent::manipulate(\$manipulation);
					}
				}
			");
        }

        require_once $file;

        /** @var SS_Database $captured */
        $captured = new $dbClass($databaseConfig);

        // Framework 3.2+ ORM needs some dependencies set
        if (method_exists($captured, 'setConnector')) {
            $captured->setConnector($current->getConnector());
            $captured->setQueryBuilder($current->getQueryBuilder());
            $captured->setSchemaManager($current->getSchemaManager());
        }

        // The connection might have had it's name changed (like if we're currently in a test)
        $captured->selectDatabase($current->currentDatabase());

        \DB::setConn($captured);
    }

    public static function handle_manipulation($manipulation)
    {
		$auditLogger = \Injector::inst()->get('AuditLogger');

        $currentMember = \Member::currentUser();
        if (!($currentMember && $currentMember->exists())) {
            return false;
        }

        foreach ($manipulation as $table => $details) {
            if (!in_array($details['command'], array('update', 'insert'))) {
                continue;
            }

            // logging writes to specific tables (just not when logging in, as it's noise)
            if (in_array($table, array('Member', 'Group', 'PermissionRole')) && !preg_match('/Security/', @$_SERVER['REQUEST_URI'])) {
                $data = $table::get()->byId($details['id']);
                if (!$data) {
                    continue;
                }
                $actionText = 'modified '.$table;

                $extendedText = '';
                if ($table == 'Group') {
                    $extendedText = sprintf(
                        'Effective permissions: %s',
                        implode(array_values($data->Permissions()->map('ID', 'Code')->toArray()), ', ')
                    );
                }
                if ($table == 'PermissionRole') {
                    $extendedText = sprintf(
                        'Effective groups: %s, Effective permissions: %s',
                        implode(array_values($data->Groups()->map('ID', 'Title')->toArray()), ', '),
                        implode(array_values($data->Codes()->map('ID', 'Code')->toArray()), ', ')
                    );
                }
                if ($table == 'Member') {
                    $extendedText = sprintf(
                        'Effective groups: %s',
                        implode(array_values($data->Groups()->map('ID', 'Title')->toArray()), ', ')
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
            if ($table == 'Group_Roles') {
                $role = \PermissionRole::get()->byId($details['fields']['PermissionRoleID']);
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
            if ($table == 'Group_Members') {
                $member = \Member::get()->byId($details['fields']['MemberID']);
                $group = \Group::get()->byId($details['fields']['GroupID']);

                // if the user isn't already in the group, log they've been added
                if (!\DB::query(sprintf(
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
        $member = \Member::currentUser();
        if (!($member && $member->exists())) {
            return false;
        }

        $effectiveViewerGroups = '';
        if ($this->owner->CanViewType == 'OnlyTheseUsers') {
            $effectiveViewerGroups = implode(array_values($original->ViewerGroups()->map('ID', 'Title')->toArray()), ', ');
        }
        if (!$effectiveViewerGroups) {
            $effectiveViewerGroups = $this->owner->CanViewType;
        }

        $effectiveEditorGroups = '';
        if ($this->owner->CanEditType == 'OnlyTheseUsers' && $original->EditorGroups()->exists()) {
            $groups = array();
            foreach ($original->EditorGroups() as $group) {
                $groups[$group->ID] = $group->Title;
            }
            $effectiveEditorGroups = implode(array_values($groups), ', ');
        }
        if (!$effectiveEditorGroups) {
            $effectiveEditorGroups = $this->owner->CanEditType;
        }

        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) published %s "%s" (ID: %s, Version: %s, ClassName: %s, Effective ViewerGroups: %s, Effective EditorGroups: %s)',
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
        $member = \Member::currentUser();
        if (!($member && $member->exists())) {
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
        $member = \Member::currentUser();
        if (!($member && $member->exists())) {
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
        $member = \Member::currentUser();
        if (!($member && $member->exists())) {
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
        $member = \Member::currentUser();
        if (!($member && $member->exists())) {
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
        $member = \Member::currentUser();
        if (!($member && $member->exists())) {
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
    public function memberLoggedIn()
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

    public function onBeforeInit()
    {
        self::bind_manipulation_capture();
    }

    /**
     * Log permission failures (where the status is set after init of page).
     */
    public function onAfterInit()
    {
        // Suppress errors if dev/build necessary
        if (!\Security::database_is_ready()) {
            return false;
        }
        $currentMember = \Member::currentUser();
        if (!($currentMember && $currentMember->exists())) {
            return false;
        }

        $statusCode = $this->owner->getResponse()->getStatusCode();

        if (substr($statusCode, 0, 1) == '4') {
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
    public function memberLoggedOut()
    {
        $this->getAuditLogger()->info(sprintf(
            '"%s" (ID: %s) successfully logged out',
            $this->owner->Email ?: $this->owner->Title,
            $this->owner->ID
        ));
    }
}
