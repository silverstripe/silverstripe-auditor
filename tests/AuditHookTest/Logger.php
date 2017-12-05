<?php

namespace SilverStripe\Auditor\Tests\AuditHookTest;

use Psr\Log\AbstractLogger;

class Logger extends AbstractLogger
{
    protected $messages = [];

    public function log($level, $message, array $context = [])
    {
        array_push($this->messages, $message);
    }

    public function getLastMessage()
    {
        return end($this->messages);
    }

    public function getMessages()
    {
        return $this->messages;
    }
}
