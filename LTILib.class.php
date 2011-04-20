<?php

/**
 * LTILib facilities registration and communication between LTI consumers
 * and providers.
 *
 * This library is designed for use by providers. A provider can use this library
 * to first register itself with the consumer and, on subsequent requests, authenticate
 * the consumer using a shared secret key.
 *
 * Upon instantiation LTILib creates a basic LTILibProvider object, but this will need
 * its profile XML modified with your own, which can be done with LTILib->getProvider()
 * ->setProfileXML().
 *
 * For registrations, the LTILib::register() method provides two callbacks, one for
 * validating the consumer profile and one for performing actions when registration is
 * successful. A typical use of this library will use the first callback to check
 * the capabilities, services and security profiles offered by the consumer. The second
 * callback would be used to save the consumer information to a database along with
 * the shared secret, which is required to authenticate further requests from the consumer.
 *
 * The library throws LTILibExceptions for your own code to handle. These are invariably
 * fatal. The LTILibValidationException is thrown when the validation callback in the
 * LTILib::register() method fails, which allows you to provide more detail. The
 * LTILibRegistrationException is thrown when the registration with the consumer
 * failed.
 */
class LTILib {
	
	private $packet;
	private $consumer;
	private $provider;
	private $authenticated = false;
	
	const LTI_TCP = 'http://www.imsglobal.org/xsd/imsltiTCP_v1p0';
	const LTI_PC = 'http://www.imsglobal.org/xsd/imsltiPC_v1p0';
	const LTI_SEC = 'http://www.imsglobal.org/xsd/imsltiSEC_v1p0';

	/**
	 * Construct a new instance of LTILib, providing a $source from which the
	 * consumer packet will be extracted.
	 *
	 * @param $source A list of variables supplied by the consumer
	 */
	public function __construct($source) {

		// first get the deployment data
		$this->extractRequestPacket($source);

		// create a base provider
		$this->provider = new LTILibProvider();
	}

	/**
	 * Register a new tool with the consumer. This method provides two
	 * callbacks which can be used to validate the consumer and perform
	 * some action when registration was successful.
	 *
	 * The $consumerValidationCallback is supplied a $consumer parameter
	 * which contains the Consumer object.
	 *
	 * The $onSuccessCallback is supplied the $tool_proxy_guid from the
	 * successful registration, the $consumer object and the $packet which
	 * contains the initial data sent by the consumer.
	 * 
	 * @param callback $consumerValidationCallback
	 * @param callback $onSuccessCallback
	 */
	public function register($consumerValidationCallback, $onSuccessCallback, $redirect = true) {
		
		if (!$this->packet || !isset($this->packet->tc_profile_url)) {
			throw new LTILibException("Could not determine service URL");
		}
		
		// legitimate service?
		// TODO: make this generic
		//$response = drupal_http_request($this->packet->tc_profile_url);
		
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $this->packet->tc_profile_url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$response = curl_exec($ch);
		
		if (curl_errno($ch)) throw new LTILibException("Could not connect to service ({$response->error})");
		else if (($code = curl_getinfo($ch, CURLINFO_HTTP_CODE)) != 200) throw new LTILibException("Unexpected code from service ({$code}, expected 200)");
		
		curl_close($ch);
		
		$profile = simplexml_load_string($response);
		$profile->registerXPathNamespace('tcp', LTILib::LTI_TCP);
		$profile->registerXPathNamespace('pc', LTILib::LTI_PC);
		$profile->registerXPathNamespace('sec', LTILib::LTI_SEC);

		$this->consumer = $this->extractConsumer($profile);
		$this->consumer->setProfileXML($response);

		if (!$consumerValidationCallback($this->consumer)) {
			throw new LTILibValidationException("Consumer does not meet validation requirements.");
		}

		try {
			$guid = $this->registerProvider();
		} catch (LTIRegistrationException $e) {
			throw $e;
		}

		// run the onSuccess callback
		$onSuccessCallback($guid, $this->consumer, $this->packet);

		// redirect back to the consumer
		if ($redirect) {
			header('Location: ' . $this->packet->launch_presentation_return_url . '&status=success', true, 301);
		}
	}

	/**
	 * Register this provider with the consumer using the SOAP service. Upon success,
	 * return the tool_proxy_guid provided by the consumer, or false if registration
	 * was unsuccessful.
	 *
	 * @return tool_proxy_guid on success, false on failure
	 */
	private function registerProvider() {

		$client = new SoapClient($this->consumer->getService('RegistrationService')->getWsdl(), array( 'trace' => 1 ));
		$var = new SoapVar(sprintf($this->getSOAPSecurityHeader(), 'lti-tool-registration', $this->packet->reg_password), XSD_ANYXML);
		$client->__setSoapHeaders(new SoapHeader('http://im.not.sure.why/this/needs/to/be/here', 'sec', $var));

		try {
			$r = $client->registerTool(array('schema_version' => 'imp', 'tool_registration_request' => $this->provider->getProfileXML()));
			$r = simplexml_load_string($r->tool_registration_response);
			$guid = (string) $r->tool_proxy_guid;

			$h = simplexml_load_string($client->__getLastResponse());
			$h->registerXPathNamespace('ims', 'http://www.imsglobal.org/services/ltiv2p0/tregv1p0/wsdl11/sync/imsltitreg_v1p0');

			if (!count($h->xpath('//ims:imsx_codeMajor[text()="success"]'))) {
				$reason = $h->xpath('//ims:imsx_description/text()');
				throw new Exception("[SoapClient] " . (string) $reason[0]);
			} else {
				return $guid;
			}
		} catch (Exception $e) {
			throw new LTILibRegistrationException($e->getMessage());
		}

		return false;
	}

	/**
	 * Perform a mac authentication on the consumer request. On successful validation this instance
	 * of LTILib will have its authenticated flag set to true.
	 *
	 * @param $secret This is the shared secret that was provided to the consumer
	 *	when this tool was first registered
	 */
	public function authenticate($secret) {
		
		$guid = $this->packet->tool_proxy_guid;
		$mac = $this->packet->mac;
		
		$authPacket = (array) $this->packet;
		unset($authPacket['mac']);
		ksort($authPacket);
		
		if ($mac == $this->generateMac($secret, $authPacket)) {
			$this->authenticated = true;
		} else {
			throw new LTILibException("Could not authenticate; MAC check failed");
		}
	}

	public function getConsumer() {
	 return $this->consumer;
	}

	public function getProvider() {
	 return $this->provider;
	}
	
	/**
	 * Extract data from a consumer profile and then create and return a
	 * new instance of LTILibConsumer
	 *
	 * @param $profile A SimpleXML object of the consumer profile XML
	 * @return a new LTILibConsumer instance
	 */
	private function extractConsumer($profile) {
		
		$vendorCode = $this->extractXPathValue($profile->xpath('//tcp:vendor/pc:code'));
		$vendorName = $this->extractXPathValue($profile->xpath('//tcp:vendor/pc:name'));
		$code = $this->extractXPathValue($profile->xpath('//tcp:tool_consumer_info/pc:code'));
		$name = $this->extractXPathValue($profile->xpath('//tcp:tool_consumer_info/pc:name'));
		$version = $this->extractXPathValue($profile->xpath('//tcp:tool_consumer_info/pc:version'));
		$guid = $this->extractXPathValue($profile->xpath('//tcp:tool_consumer_instance/tcp:guid'));;
		$services = $this->extractConsumerServices($profile);
		$capabilities = $this->extractConsumerCapabilities($profile);
		$securityProfiles = $this->extractConsumerSecurityProfiles($profile);

		return new LTILibConsumer($vendorCode, $vendorName, $code, $name,
				$version, $guid, $services, $capabilities, $securityProfiles);
	}

	/**
	 * Extract services from a consumer profile XML.
	 *
	 * @param $profile The simpleXML object
	 * @return Array of LTILibConsumerService objects
	 */
	private function extractConsumerServices($profile) {

		$services = array();

		foreach ($profile->xpath('//pc:service_profile/pc:service') as $service) {
			$url = (string) $service->attributes()->url;
			$wsdl = (string) $service->attributes()->wsdl;
			$version = (string) $service->attributes()->version;
			$name = (string) $service->attributes()->name;
			$namespace = (string) $service->attributes()->namespace;

			$services[] = new LTILibConsumerService($url, $wsdl, $version, $name, $namespace);
		}

		return $services;
	}

	/**
	 * Extract capabilities from a consumer profile XML.
	 *
	 * @param $profile The simpleXML object
	 * @return Array of LTILibConsumerCapability objects
	 */
	private function extractConsumerCapabilities($profile) {

		$capabilities = array();

		foreach ($profile->xpath('//tcp:capabilities_offered/pc:capability') as $cap) {
			$name = $this->extractXPathValue($cap->xpath('text()'));
			$capabilities[] = new LTILibConsumerCapability($name);
		}

		return $capabilities;
	}

	/**
	 * Extract security profiles from a consumer profile XML.
	 *
	 * @param $profile The simpleXML object
	 * @return Array of LTILibConsumerSecurityProfile objects
	 */
	private function extractConsumerSecurityProfiles($profile) {

		$securityProfiles = array();

		foreach ($profile->xpath('//tcp:security_profiles/*') as $node) {
			$name = $node->getName();
			$config = array();

			switch ($name) {
				case 'basic_hash_message_security_profile':
					$config['algorithm'] = $this->extractXPathValue($node->xpath('sec:algorithm/text()'));
					break;
			}

			$securityProfiles[] = new LTILibConsumerSecurityProfile($name, $config);
		}

		return $securityProfiles;
	}

	/**
	 * Shortcut utility method for extracting a single XPath value
	 *
	 * @param $result A SimpleXML XPath result
	 * @return The string representation of the first item in the $result
	 */
	private function extractXPathValue($result) {
		if (empty($result)) return '';
		if (!is_array($result)) return '';
		return (string) $result[0];
	}

	/**
	 * Returns the consumer packet as an object
	 * @return The consumer packet object
	 */
	public function getPacket() {
		return $this->packet;
	}

	/**
	 * Extract the consumer request packet
	 * @param $vars The raw packet (i.e. $_POST array)
	 */
	private function extractRequestPacket($vars) {
		
		$this->packet = (object) $vars;
		//$this->packet = (object)
		//	array_intersect_key($vars, array_merge($this->getLaunchPacket(), $this->getRegPacket()));
	}
	
	private function getLaunchPacket() {
		return array(
			'user_id' => 1,
			'roles' => 1,
			'launch_presentation_locale' => 1,
			'launch_presentation_css_url' => 1,
			'launch_presentation_document_target' => 1,
			'launch_presentation_window_name' => 1,
			'launch_presentation_width' => 1,
			'launch_presentation_height' => 1,
			'launch_presentation_return_url' => 1,
		);
	}
	
	private function getRegPacket() {
		return array(
			'reg_password' => 1,
			'tool_version' => 1,
			'tool_code' => 1,
			'vendor_code' => 1,
			'tc_profile_url' => 1,
		);
	}

	private function getSOAPSecurityHeader() {
		return LTILib::SOAP_SECURITY_HEADER;
	}

	public function isAuthenticated() {
		return $this->authenticated;
	}

	private function generateMac($secret, $authPacket) {
		return base64_encode(
			hash('sha1', join( '', array_values($authPacket)) . $secret, true)
		);
	}

	const SOAP_SECURITY_HEADER = <<<XML
<wsse:Security
	SOAP-ENV:mustUnderstand="1"
	xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
	<wsse:UsernameToken wsu:Id="UsernameToken-4" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
		<wsse:Username>%s</wsse:Username>
		<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">%s</wsse:Password>
	</wsse:UsernameToken>
  </wsse:Security>
  <ims:imsx_syncRequestHeaderInfo xmlns:ims="http://www.imsglobal.org/services/ltiv2p0/tregv1p0/wsdl11/sync/imsltitreg_v1p0">
		<ims:imsx_version>V1.0</ims:imsx_version>
		<ims:imsx_messageIdentifier></ims:imsx_messageIdentifier>
 </ims:imsx_syncRequestHeaderInfo>
XML;
}

/**
 * Represents an LTI provider.
 */
class LTILibProvider {

	private $profileXML;

	function __construct() {
		$this->profileXML = <<<XML
<?xml version="1.0"?>
<tool_registration_request xmlns="http://www.imsglobal.org/services/ltiv2p0/ltirgsv1p0/imsltiRGS_v1p0"
						   xmlns:sec="http://www.imsglobal.org/xsd/imsltiSEC_v1p0"
				           xmlns:tp="http://www.imsglobal.org/xsd/imsltiTPR_v1p0"
				           xmlns:cm="http://www.imsglobal.org/xsd/imsltiMSS_v1p0"
				           xmlns:pc="http://www.imsglobal.org/xsd/imsltiPC_v1p0">
  <tool_profile lti_version="2.0"/>
</tool_registration_request>
XML;
	}

	public function getProfileXML() {
	 return $this->profileXML;
	}

	public function setProfileXML($profileXML) {
	 $this->profileXML = $profileXML;
	}
}

/**
 * Represents an LTI consumer.
 */
class LTILibConsumer {
	
	private $vendorCode;
	private $vendorName;
	private $code;
	private $name;
	private $version;
	private $guid;
	
	private $services = array();
	private $capabilities = array();
	private $securityProfiles = array();

	private $profileXML;

	function __construct($vendorCode, $vendorName, $code, $name, $version, $guid, $services, $capabilities, $securityProfiles) {
		$this->vendorCode = $vendorCode;
		$this->vendorName = $vendorName;
		$this->code = $code;
		$this->name = $name;
		$this->version = $version;
		$this->guid = $guid;

		// index the services by name
		foreach ($services as $service) {
			$this->services[$service->getName()] = $service;
		}
		
		foreach ($capabilities as $cap) {
			$this->capabilities[$cap->getName()] = $cap;
		}

		foreach ($securityProfiles as $profile) {
			$this->securityProfiles[$profile->getName()] = $profile;
		}
	}

	public function getVendorCode() {
		return $this->vendorCode;
	}

	public function getVendorName() {
		return $this->vendorName;
	}

	public function getCode() {
		return $this->code;
	}

	public function getName() {
		return $this->name;
	}

	public function getVersion() {
		return $this->version;
	}

	public function getGuid() {
		return $this->guid;
	}

	public function getServices() {
		return $this->services;
	}

	/**
	 * Return a specific service.
	 *
	 * @param $id The id of the service to return
	 * @return an LTILibConsumerService object if the $id exists, or false
	 */
	public function getService($id) {
		if (isset($this->services[$id])) return $this->services[$id];
		return false;
	}

	public function getSecurityProfiles() {
		return $this->securityProfiles;
	}

	/**
	 * Return a specific security profile.
	 *
	 * @param $id The id of the security profile to return
	 * @return an LTILibConsumerSecurityProfile object if the $id exists, or false
	 */
	public function getSecurityProfile($id) {
		if (isset($this->securityProfiles[$id])) return $this->securityProfiles[$id];
		return false;
	}

	public function getCapabilities() {
	 return $this->capabilities;
	}

	/**
	 * Check if this LTI consumer offers a list of capabilities. If any one of the
	 * capabilities listed in $capabilities (which is an array of strings) is missing,
	 * return false.
	 *
	 * @param $capabilities array of capabilities as strings
	 * @return true if all capabilities are offered by the consumer
	 */
	public function hasCapabilities($capabilities) {
		foreach ($capabilities as $req) {
			if (!array_key_exists($req, $this->capabilities)) return false;
		}
		return true;
	}

	public function getProfileXML() {
	 return $this->profileXML;
	}

	public function setProfileXML($profileXML) {
	 $this->profileXML = $profileXML;
	}
}

/**
 * Represents an LTI consumer service.
 */
class LTILibConsumerService {
	
	private $url;
	private $wsdl;
	private $version;
	private $name;
	private $namespace;
	
	public function __construct($url, $wsdl, $version, $name, $namespace) {
		$this->url = $url;
		$this->wsdl = $wsdl;
		$this->version = $version;
		$this->name = $name;
		$this->namespace = $namespace;
	}

	public function getUrl() {
	 return $this->url;
	}

	public function getWsdl() {
	 return $this->wsdl;
	}

	public function getVersion() {
	 return $this->version;
	}

	public function getName() {
	 return $this->name;
	}

	public function getNamespace() {
	 return $this->namespace;
	}
}

/**
 * Represents an LTI consumer capability.
 */
class LTILibConsumerCapability {
	
	private $name;
	
	public function __construct($name) {
		$this->name = $name;
	}
	
	public function getName() {
		return $this->name;
	}

	public function __toString() {
		return $this->name;
	}
}

/**
 * Represents an LTI consumer security profile.
 */
class LTILibConsumerSecurityProfile {

	private $name;
	private $config;

	public function __construct($name, $config) {
		$this->name = $name;
		$this->config = $config;
	}

	public function getName() {
		return $this->name;
	}

	/**
	 * Return a specific config item if it exists.
	 * @param $key The config key to return
	 * @return The config value or false
	 */
	public function getConfigItem($key) {
		if (isset($this->config[$key])) {
			return $this->config[$key];
		}
		return false;
	}
	
}

class LTILibException extends Exception {
	
	public function __construct($message, $code = 0, Exception $prev = null) {
		parent::__construct($message, $code, $prev);
	}
}

class LTILibValidationException extends LTILibException {

	public function __construct($message, $code = 0, Exception $prev = null) {
		parent::__construct($message, $code, $prev);
	}
}

class LTILibRegistrationException extends LTILibException {

	public function __construct($message, $code = 0, Exception $prev = null) {
		parent::__construct($message, $code, $prev);
	}
}


