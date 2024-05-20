<?php

namespace SilverStripe\Auditor\Extensions;

use SilverStripe\Core\Extension;
use SilverStripe\Auditor\AuditHook;

class DatabaseExtension extends Extension
{
    protected function onBeforeManipulate(array &$manipulation)
    {
        AuditHook::handle_manipulation($manipulation);
    }
}
