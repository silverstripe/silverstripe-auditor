<?php

namespace SilverStripe\Auditor\Tests\AuditHookTest;

use Psr\Log\AbstractLogger;
use SilverStripe\Dev\TestOnly;

class Logger extends AbstractLogger implements TestOnly
{
    protected $messages = [];

    public function log($level, string|\Stringable $message, array $context = []): void
    {
        $this->messages[] = $message . ' ' . json_encode($context);
    }

    public function getLastMessage()
    {
        return (string) end($this->messages);
    }

    public function getMessages()
    {
        return $this->messages;
    }
}
