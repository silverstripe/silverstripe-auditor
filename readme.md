# SilverStripe Auditor

[![Build Status](http://img.shields.io/travis/silverstripe/silverstripe-auditor.svg?style=flat-square)](https://travis-ci.org/silverstripe/silverstripe-auditor)
[![Code Quality](http://img.shields.io/scrutinizer/g/silverstripe/silverstripe-auditor.svg?style=flat-square)](https://scrutinizer-ci.com/g/silverstripe/silverstripe-auditor)

Auditor module installs a series of extension hooks into the Framework to monitor activity of authenticated users. Audit
trail is written into `LOG_AUTH` syslog facility through [Monolog](https://github.com/Seldaek/monolog/), and includes:

* Login attempts (failed and successful)
* Logouts
* Page manipulations that may potentially affect the live site
* Security-related changes such as Members being added to groups or permission changes.

## Warning: do not use SS_SysLogWriter!

Using `SS_SysLogWriter` while this module is in operation will cause weird errors where logs may not be written to
intended facility (i.e. you may see PHP errors coming up in the auth log). You can still use `SS_Log`, as long as you
don't use this writer, or you can use `SilverStripe\Auditor\MonologSysLogWriter` provided with this module instead:

```php
SS_Log::add_writer(new \SilverStripe\Auditor\MonologSysLogWriter(), SS_Log::DEBUG, '<=');
```

This happens because PHP provides only one static API for accessing the syslog: `openlog` and `syslog` calls. There is
no way to change the facility for only one syslog event, which means `openlog` needs to be called before each `syslog`.
Unfortunately `SS_SysLogWriter` does not do that (neither does underlying `Zend_Log_Writer_Syslog`).

## Installation

```sh
$ composer require silverstripe/auditor
```

## Custom audit trail

You can add your own logs to the audit trail by accessing the `AuditLogger`, which is easiest done through the Injector:

```php
class MyPage_Controller extends ContentController
{
	private static $dependencies = array(
		'auditLogger' => '%$AuditLogger'
	);
}
```

AuditLogger is guaranteed to implement the [PSR-3 LoggerInterface](https://github.com/php-fig/log/blob/master/Psr/Log/LoggerInterface.php),
events can be logged at multiple levels, with arbitrary context:

```php
function dostuff()
{
	$this->auditLogger->info('stuff happened');
	// You can also pass an arbitrary context array which will be included in the log.
	$this->auditLogger->warn('stuff happened', ['defcon'=>'amber']);
}
```

Here is what will appear in the audit log on your dev machine (the exact format will depend on your operating system):

	Aug 24 11:09:02 SilverStripe_audit[80615]: stuff happened [] {"real_ip":"127.0.0.1","url":"/do-stuff/","http_method":"GET","server":"localhost","referrer":null}
	Aug 24 11:09:02 SilverStripe_audit[80615]: stuff happened {"defcon":"amber"} {"real_ip":"127.0.0.1","url":"/do-stuff/","http_method":"GET","server":"localhost","referrer":null}

## Troubleshooting

We are using a dynamically generated class for capturing database manipulation events. This class is cached, and in
some cases it may retain an old, incorrect version of the class. You can wipe it by removing your cache, specifically
the file called `<ss-cache-dir>/<user>/.cache.CLC.SearchManipulateCapture_MySQLDatabase`.

## Contributing

Submitting a pull-request gives the highest likelihood of getting a bug fixed or a feature added.


## License ##

	Copyright (c) 2006-2016, SilverStripe Limited - www.silverstripe.com
	All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
	      documentation and/or other materials provided with the distribution.
	    * Neither the name of SilverStripe nor the names of its contributors may be used to endorse or promote products derived from this software
	      without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
	GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
	STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
	OF SUCH DAMAGE.
