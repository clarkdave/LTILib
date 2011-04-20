# LTILib

A PHP library for LTI providers for communication over the [Full LTI specification](http://www.imsglobal.org/lti/index.html). Because the Full LTI specification is not fully public, this library is unfinished but should provide a good starting point for any PHP applications serving as LTI providers.

# Examples

## Register a new LTI consumer

	$lti = new LTILib($consumerSource);
	
	$lti->getProvider()->setProfileXML('<tool_registration_request>...');
	
	$lti->register(
		function($consumer) {
			// check capabilities
			if (!$consumer->hasCapabilities(array('menulink-category-context-tool'))) return false;

			// check security
			if (!$profile = $consumer->getSecurityProfile('basic_hash_message_security_profile')) return false;
			
			// SHA-1 encryption required
			if ($profile->getConfigItem('algorithm') != 'SHA-1') return false;
			
			return true;
		},
		function ($tool_proxy_guid, $consumer, $packet) {
			// registration was successful, celebrate in this callback!
		}
	);
	
## License 

(The MIT License)

Copyright (c) 2010-2011 Dave Clark (me@clarkdave.net)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.