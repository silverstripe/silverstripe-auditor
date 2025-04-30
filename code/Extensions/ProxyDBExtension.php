<?php

namespace SilverStripe\Auditor\Extensions;

use SilverStripe\Auditor\AuditHook;
use SilverStripe\Core\Extension;
use TractorCow\ClassProxy\Generators\ProxyGenerator;
use TractorCow\SilverStripeProxyDB\ProxyDBFactory;
use SilverStripe\Dev\Deprecation;

/**
 * @extends Extension<ProxyDBFactory>
 *
 * @deprecated 3.2.0 Will be replaced with an extension on SilverStripe\ORM\Connect\Database in a future major release
 */
class ProxyDBExtension extends Extension
{
    public function __construct()
    {
        Deprecation::withSuppressedNotice(function () {
            Deprecation::notice(
                '3.2.0',
                'Will be replaced with an extension on SilverStripe\ORM\Connect\Database in a future major release.',
                Deprecation::SCOPE_CLASS
            );
        });
    }

    /**
     * Bind a proxy callback into the Database::manipulate method to allow us to track database activity
     * for the {@link AuditHook} class
     *
     * @param ProxyGenerator $proxy
     */
    public function updateProxy(ProxyGenerator &$proxy)
    {
        $proxy = $proxy->addMethod('manipulate', function ($args, $next) {
            $manipulation = $args[0];
            AuditHook::handle_manipulation($manipulation);
            return $next(...$args);
        });
    }
}
