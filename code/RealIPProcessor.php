<?php

namespace SilverStripe\Auditor;

use SilverStripe\Core\Injector\Injector;
use SilverStripe\Control\HTTPRequest;

class RealIPProcessor
{
    public function __invoke(array $record)
    {
        $req = Injector::inst()->create(HTTPRequest::class, null, null);
        $record['extra']['real_ip'] = $req->getIP();
        return $record;
    }
}
