<?php

namespace SilverStripe\Auditor;

class RealIPProcessor
{

    public function __invoke(array $record)
    {
		$req = \Injector::inst()->create('SS_HTTPRequest', null, null);
		$record['extra']['real_ip'] = $req->getIP();
		return $record;
	}

}
