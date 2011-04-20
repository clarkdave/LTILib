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