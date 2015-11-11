<?php

class Crypt
{
	
	/**
	 * Perform and return a Blowfish hash on the given string. Strength value must be in the range 04-31
	 * Use this for password hashes.
	 */
	public static function hash_blowfish($toHash, $strength='07'){
		return crypt($toHash, '$2a$'.str_pad($strength, 2, '0', STR_PAD_LEFT).'$'.Crypt::rand_alphanumeric(22).'$');
	}
	
	/**
	 * Verify whether or not an input matches the stored hash. Works with any hash created by php's crypt (Like blowfish).
	 */
	public static function verify($userInput, $storedHash){
		return (crypt($userInput, $storedHash) == $storedHash);
		// Safer method below only available in >= PHP 5.6.0
		//return hash_equals($storedHash, crypt($userInput, $storedHash));
	}
	
	/**
	 * Generate random alpha-numeric string of specified length
	 */
	public static function rand_alphanumeric($length){
		return Crypt::rand_string('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', $length);
	}
	
	/**
	* Generate a good random integer
	* @param int $min Minumim value
	* @param int $max Maximum value
	* @return int Integer within range
	*/
	public static function rand_int($min, $max){
			mt_srand(Crypt::make_seed());
		return mt_rand($min, $max);
	}
	
	/**
	 * Generate random string of specified length based off the given string of characters
	 */
	public static function rand_string($characters, $length){
		$string = '';
		mt_srand(Crypt::make_seed());
		for ($p = 0; $p < $length; $p++) {
			$string .= $characters[mt_rand(0, strlen($characters)-1)];
		}
		return $string;
	}
	
	/**
	 * Base64 encode a string and make it URL safe (Must decode with base64url_decode from this object)
	 */
	public static function base64url_encode($data) { 
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); 
	}
	
	/**
	 * Base64 decode a string from a URL that was encoded using base64url_encode from this object
	 */
	public static function base64url_decode($data) { 
		return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT)); 
	}
	
	/**
	* Take a number or numerical string and format as float
	* Supports US and UK formats. Designed for money but will work with other formats as well.
	* @param mixed $amount
	* @param int $decimal_places
	* @param int $round_mode
	* @return float
	*/
	public static function money_float($amount, $decimal_places=2, $round_mode=PHP_ROUND_HALF_UP){
		if(empty($amount)){
			$amount = 0;
		}
		else if(is_object($amount)){
			$amount = (string)$amount;
		}
		if(is_string($amount)){
			$amount = trim($amount, "\$Â£â‚¬Â¥ \t\n\r\0\x0B");
			// Strip thousands separator
			$comma = 0+strrpos($amount, ',');
			$period = 0+strrpos($amount, '.');
			$len = strlen($amount);
			// Strip thousands separator
			if($period || $comma){
				if($comma && ($period > $comma || (!$period && ($len - $comma -1) % 3 == 0))){
					$amount = str_replace(',','',$amount);
				}
				else if($period && ($comma > $period || (!$comma && ($len - $period -1) % 3 == 0))){
					$amount = str_replace('.','',$amount);
				}
			}
			$amount = floatval($amount);
		}
		return round(number_format($amount, $decimal_places+1, '.', ''), $decimal_places);
	}
	
	/**
	 * Generate and return a GUID v4 string. If data is null, returned guid will be random and secure.
	 * @param string $data Optional binary sstring of length 16 to format as GUID. This leaves it up to the caller to generate the random string.
	 * @return string GUID v4 formatted string without surrounding braces
	 */
	public static function guidv4($data=null){
		if(!$data){
			$data = openssl_random_pseudo_bytes(16);
		}
		assert(strlen($data) == 16);

		$data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
		$data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

		return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
	}
	
	/**
	 * Generate a seed based off the time
	 */
	private static function make_seed(){
		list($usec, $sec) = explode(' ', microtime());
		return (float) $sec + ((float) $usec * 100000);
	}
	
	/**
	 * Encrypts a string using a constant public key.
	 * Throws an error on failure
	 * @param string $pem_location path to public .pem file
	 * @param mixed $data String to encrypt. Also accepts 1D array and will encrypt all the values (not keys)
	 * @return string Encrypted string in base64
	 */
	public static function encrypt($pem_location, $data){
		if(!$data){
			return '';
		}
		$path = "file://".$pem_location;
		$public = openssl_pkey_get_public($path);
		if(!$public){
			throw new Exception('Invalid public key file: '.$path, 109);
		}
		if(is_array($data)){
			array_walk($data, function(&$value, $key, &$public){
				if(!$value){
					return;
				}
				openssl_public_encrypt($value, $encrypted, $public, OPENSSL_PKCS1_PADDING);
				if(!$encrypted){
					throw new Exception('Error encrypting data for key: '.$key, 110);
				}
				$value = base64_encode($encrypted);
			}, $public);
			openssl_free_key($public);
			return $data;
		}
		else{
			openssl_public_encrypt($data, $encrypted, $public, OPENSSL_PKCS1_PADDING);
			openssl_free_key($public);
			if(!$encrypted){
				throw new Exception('Error encrypting data', 111);
			}
			return base64_encode($encrypted);
		}
	}
	
	/**
	 * Decrypts an encrypted string using a constant private key.
	 * Throws an error on failure
	 * @param string $pem_location path to private .pem file
	 * @param mixed $data base64 encoded string to Decrypt. Also accepts 1D array and will decrypt all the values (not keys)
	 * @return string Decrypted string
	 */
	public static function decrypt($pem_location, $data){
		if(!$data){
			return '';
		}
		$path = "file://".$pem_location;
		$private = openssl_get_privatekey($path);
		if(!$private){
			throw new Exception('Invalid private key file: '.$path, 112);
		}
		if(is_array($data)){
			array_walk($data, function(&$value, $key, &$private){
				if(!$value){
					return;
				}
				$value = base64_decode($value);
				openssl_private_decrypt($value, $decrypted, $private, OPENSSL_PKCS1_PADDING);
				if(!$decrypted){
					throw new Exception('Error decrypting data for key: '.$key, 113);
				}
				$value = $decrypted;
			}, $private);
			openssl_free_key($private);
			return $data;
		}
		else{
			$data = base64_decode($data);
			openssl_private_decrypt($data, $decrypted, $private, OPENSSL_PKCS1_PADDING);
			openssl_free_key($private);
			if(!$decrypted){
				throw new Exception('Error decrypting data', 114);
			}
			return $decrypted;
		}
	}
}