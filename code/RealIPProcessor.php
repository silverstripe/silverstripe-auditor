<?php

namespace SilverStripe\Auditor;

use Monolog\LogRecord;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;

class RealIPProcessor
{
    public function __invoke(LogRecord $record)
    {
        $req = Injector::inst()->create(HTTPRequest::class, null, null);
        $record['extra']['real_ip'] = $req->getIP();
        return $record;
    }
}
