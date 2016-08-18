# SilverStripe Auditor

[![Build Status](http://img.shields.io/travis/silverstripe-labs/silverstripe-auditor.svg?style=flat-square)](https://travis-ci.org/silverstripe-labs/silverstripe-auditor)
[![Code Quality](http://img.shields.io/scrutinizer/g/silverstripe-labs/silverstripe-auditor.svg?style=flat-square)](https://scrutinizer-ci.com/g/silverstripe-labs/silverstripe-auditor)

Auditor module installs a series of extension hooks into the Framework to monitor activity of authenticated users. Audit
trail is written into `LOG_AUTH` facility, and includes:

* Login attempts (failed and successful), logouts
* Live site page manipulations
* Security-related changes such as Members being added and removed from groups, being given permissions, or roles.

## Installation

```sh
$ composer require silverstripe/auditor
```

## Contributing

Submitting a pull-request gives a highest likelihood of getting a bug fixed or a feature added.


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
