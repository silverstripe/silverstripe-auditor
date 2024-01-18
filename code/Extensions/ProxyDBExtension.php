<?php

namespace SilverStripe\Auditor\Extensions;

use SilverStripe\Auditor\AuditHook;
use SilverStripe\Core\Extension;
use TractorCow\ClassProxy\Generators\ProxyGenerator;
use TractorCow\SilverStripeProxyDB\ProxyDBFactory;

/**
 * @extends Extension<ProxyDBFactory>
 */
class ProxyDBExtension extends Extension
{
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
