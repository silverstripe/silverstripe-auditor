<?php

namespace SilverStripe\Auditor;

enum AuditedEventType: string
{
    case CREATE = 'create';
    case READ = 'read';
    case UPDATE = 'update';
    case DELETE = 'delete';
    case NOTICE = 'notice';
}
