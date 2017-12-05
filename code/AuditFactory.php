<?php

namespace SilverStripe\Auditor;

use Exception;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\SyslogHandler;
use Monolog\Logger;
use Monolog\Processor\WebProcessor;
use SilverStripe\Core\Injector\Factory;

/**
 * Logs are written using a side-channel, because audit trail should not be mixed
 * up with regular PHP errors.
 */
class AuditFactory implements Factory
{
    public function create($service, array $params = [])
    {
        if (!empty($params)) {
            throw new Exception('AuditFactory does not support passing params.');
        }

        $obj = null;
        switch ($service) {
            case 'AuditLogger':
                $log = new Logger('audit');
                $syslog = new SyslogHandler('SilverStripe_audit', LOG_AUTH, Logger::DEBUG);
                $syslog->pushProcessor(new WebProcessor($_SERVER, [
                    'url'         => 'REQUEST_URI',
                    'http_method' => 'REQUEST_METHOD',
                    'server'      => 'SERVER_NAME',
                    'referrer'    => 'HTTP_REFERER',
                ]));

                $syslog->pushProcessor(new RealIPProcessor());
                $formatter = new LineFormatter("%level_name%: %message% %context% %extra%");
                $syslog->setFormatter($formatter);
                $log->pushHandler($syslog);

                return $log;
            default:
                throw new Exception(sprintf("AuditFactory does not support creation of '%s'.", $service));
        }
    }
}
