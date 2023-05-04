# Silverstripe Auditor

[![CI](https://github.com/silverstripe/silverstripe-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/silverstripe/silverstripe-auditor/actions/workflows/ci.yml)
[![Silverstripe supported module](https://img.shields.io/badge/silverstripe-supported-0071C4.svg)](https://www.silverstripe.org/software/addons/silverstripe-commercially-supported-module-list/)

Auditor module installs a series of extension hooks into the Framework to monitor activity of authenticated users. Audit
trail is written into `LOG_AUTH` syslog facility through [Monolog](https://github.com/Seldaek/monolog/), and includes:

* Login attempts (failed and successful)
* Logouts
* Page manipulations that may potentially affect the live site
* Security-related changes such as Members being added to groups or permission changes.

## Installation

```sh
composer require silverstripe/auditor
```

## Custom audit trail

You can add your own logs to the audit trail by accessing the `AuditLogger`, which is easiest done through the Injector:

```php
use SilverStripe\CMS\Controllers\ContentController;

class MyPageController extends ContentController
{
    private static $dependencies = [
        'auditLogger' => '%$AuditLogger'
    ];
}
```

AuditLogger is guaranteed to implement the [PSR-3 LoggerInterface](https://github.com/php-fig/log/blob/1.0.2/Psr/Log/LoggerInterface.php),
events can be logged at multiple levels, with arbitrary context:

```php
public function dostuff()
{
    $this->auditLogger->info('stuff happened');
    // You can also pass an arbitrary context array which will be included in the log.
    $this->auditLogger->warn('stuff happened', ['defcon' => 'amber']);
}
```

Here is what will appear in the audit log on your dev machine (the exact format will depend on your operating system):

```
Aug 24 11:09:02 SilverStripe_audit[80615]: stuff happened [] {"real_ip":"127.0.0.1","url":"/do-stuff/","http_method":"GET","server":"localhost","referrer":null}
Aug 24 11:09:02 SilverStripe_audit[80615]: stuff happened {"defcon":"amber"} {"real_ip":"127.0.0.1","url":"/do-stuff/","http_method":"GET","server":"localhost","referrer":null}
```

## Troubleshooting

We are using a dynamically generated class for capturing database manipulation events. This class is cached, and in
some cases it may retain an old, incorrect version of the class. You can wipe it by removing your cache, specifically
the file called `<ss-cache-dir>/<user>/.cache.CLC.SearchManipulateCapture_SilverStripeORMConnectMySQLDatabase`.

## Contributing

Submitting a pull-request gives the highest likelihood of getting a bug fixed or a feature added.
