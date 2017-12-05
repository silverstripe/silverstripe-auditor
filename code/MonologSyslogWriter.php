<?php

namespace SilverStripe\Auditor;

require_once BASE_PATH . '/framework/thirdparty/Zend/Log/Writer/Abstract.php';

/**
 * Alternative monolog writer for SS_Log, for use when auditor module is in operation.
 *
 * Supplied, because there cannot be more than one SS_SysLogWriter has problems writing
 * to more than one facility at the same time. See this module's readme for more information.
 */
class MonologSysLogWriter extends \Zend_Log_Writer_Abstract
{
    /**
     * @var array Convert Zend_Log level to Monolog level.
     */
    protected $priorities = array(
        \Zend_Log::EMERG  => \Monolog\Logger::EMERGENCY,
        \Zend_Log::ALERT  => \Monolog\Logger::ALERT,
        \Zend_Log::CRIT   => \Monolog\Logger::CRITICAL,
        \Zend_Log::ERR    => \Monolog\Logger::ERROR,
        \Zend_Log::WARN   => \Monolog\Logger::WARNING,
        \Zend_Log::NOTICE => \Monolog\Logger::NOTICE,
        \Zend_Log::INFO   => \Monolog\Logger::INFO,
        \Zend_Log::DEBUG  => \Monolog\Logger::DEBUG,
    );

    /**
     * @var Monolog\Logger
     */
    protected $monolog;

    /**
     * @param string $ident String identifying the application within the syslog stream.
     * @param $facility Syslog facility.
     */
    public function __construct($ident = 'SilverStripe_log', $facility = LOG_USER)
    {
        $this->monolog = new \Monolog\Logger('application');
        $syslog = new \Monolog\Handler\SyslogHandler($ident, $facility, \Monolog\Logger::DEBUG);
        $formatter = new \Monolog\Formatter\LineFormatter("%level_name%: %message% %context%");
        $syslog->setFormatter($formatter);
        $this->monolog->pushHandler($syslog);
    }

    public static function factory($config)
    {
        return new MonologSysLogWriter();
    }

    protected function _write($event)
    {
        if (!empty($this->priorities[$event['priority']])) {
            $level = $this->priorities[$event['priority']];
        } else {
            $level = \Monolog\Logger::INFO;
        }

        $message = sprintf(
            '%s (line %s in %s)',
            $event['message']['errstr'],
            $event['message']['errline'],
            $event['message']['errfile']
        );

        $context = [];
        if (!empty($event['info'])) {
            $context = $event['info'];
        }

        $this->monolog->log($level, $message, $context);
    }
}
