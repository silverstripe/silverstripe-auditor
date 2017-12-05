<?php

namespace SilverStripe\Auditor;

use SilverStripe\Core\Injector\Factory;

/**
 * Logs are written using a side-channel, because audit trail should not be mixed
 * up with regular PHP errors.
 */
class AuditFactory implements Factory
{
    public function create($service, array $params = array())
    {
        if (!empty($params)) {
            throw new \Exception('AuditFactory does not support passing params.');
        }

        $obj = null;
        switch ($service) {
            case 'AuditLogger':
                $log = new \Monolog\Logger('audit');
                $syslog = new \Monolog\Handler\SyslogHandler('SilverStripe_audit', LOG_AUTH, \Monolog\Logger::DEBUG);
                $syslog->pushProcessor(new \Monolog\Processor\WebProcessor($_SERVER, array(
                'url'         => 'REQUEST_URI',
                'http_method' => 'REQUEST_METHOD',
                'server'      => 'SERVER_NAME',
                'referrer'    => 'HTTP_REFERER',
                )));
                    $syslog->pushProcessor(new RealIPProcessor());
                    $formatter = new \Monolog\Formatter\LineFormatter("%level_name%: %message% %context% %extra%");
                    $syslog->setFormatter($formatter);
                    $log->pushHandler($syslog);
                return $log;
            default:
                throw new \Exception(sprintf("AuditFactory does not support creation of '%s'.", $service));
        }
    }
}
