<?php

// AuditLogger configuration for capturing administrative actions

// don't set up auth log writing in the command line, since it fills the logs with output
// from unit tests, etc. It's designed to log actions from web requests only.
// See {@link AuditLoggerTest} to see how this is tested with a test log writer
if(!Director::is_cli()) {
	$logFileWriter = new SS_SysLogWriter('SilverStripe', null, LOG_AUTH);
	$logFileWriter->setFormatter(new AuditLoggerFormatter());
	SS_Log::add_writer($logFileWriter, AuditLogger::PRIORITY, '=');
}

// AuditLogger implements hooks in the core to capture events, such as
// when a user logs in and out, publishes a page, add/remove member from group etc.
MemberLoginForm::add_extension('AuditLogger');
RequestHandler::add_extension('AuditLogger');
Controller::add_extension('AuditLogger');
Member::add_extension('AuditLogger');
SiteTree::add_extension('AuditLogger');

// override ManyManyList so that we can log particular relational changes
// such as when a Member is added to a Group or removed from it.
Object::useCustomClass('ManyManyList', 'AuditLoggerManyManyList', true);
Object::useCustomClass('Member_GroupSet', 'AuditLoggerMemberGroupSet', true);


