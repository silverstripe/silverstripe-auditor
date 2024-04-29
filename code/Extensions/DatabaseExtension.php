<?php

namespace SilverStripe\Auditor\Extensions;

use SilverStripe\Core\Extension;
use SilverStripe\Auditor\AuditHook;

class DatabaseExtension extends Extension
{
    public function onBeforeManipulate(array &$manipulation)
    {
        AuditHook::handle_manipulation($manipulation);
    }
}
