<?php



//////////
//SETTINGS
//////////



//network settings (e.g. 1.2.3.4:8080)
$proxy = '';

//cryptographic settings for RSA-SHA1 oauth_signature_method
$oauth_certificate =
'-----BEGIN CERTIFICATE-----
MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0
IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV
BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY
zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb
mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3
DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d
4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb
WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J
-----END CERTIFICATE-----';

$oauth_private_key =
'-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----';



///////////
//FUNCTIONS
///////////



//ASCII to HEX converter
function convert_to_hex($data)
{
	$result = '';
	
	$result = bin2hex($data);
	
	return $result;
}



//HEX to ASCII converter
function convert_to_character($data)
{
	$result = '';
	
	$result = pack('H*', $data);
	
	return $result;
}



//Google Authenticator compatibility
function base32_encode($data)
{
	$result = '';
	$binary_string = '';
	$binary_string_chunks = '';
	$padding_mod = 0;

	$data = strtoupper($data);

	$base32_mapping = array(
								'A' => '0',  'B' => '1',  'C' => '2',  'D' => '3',  'E' => '4',  'F' => '5',  'G' => '6',  'H' => '7',
								'I' => '8',  'J' => '9',  'K' => '10', 'L' => '11', 'M' => '12', 'N' => '13', 'O' => '14', 'P' => '15',
								'Q' => '16', 'R' => '17', 'S' => '18', 'T' => '19', 'U' => '20', 'V' => '21', 'W' => '22', 'X' => '23',
								'Y' => '24', 'Z' => '25', '2' => '26', '3' => '27', '4' => '28', '5' => '29', '6' => '30', '7' => '31'
							);
	$base32_charset = array(
								'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L',	'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T',	'U', 'V', 'W', 'X',
								'Y', 'Z', '2', '3',	'4', '5', '6', '7',
								'='
							);

	$data = str_split($data);
	for($counter = 0; $counter < count($data); $counter = $counter + 1)
	{
		$binary_string = $binary_string . str_pad(base_convert(ord($data[$counter]), 10, 2), 8, '0', STR_PAD_LEFT);
	}
	$binary_string_chunks = str_split($binary_string, 5);

	$counter = 0;
	while($counter < count($binary_string_chunks))
	{   
		$result = $result . $base32_charset[base_convert(str_pad($binary_string_chunks[$counter], 5, '0', STR_PAD_RIGHT), 2, 10)];
		$counter = $counter + 1;
	}

	$padding_mod = strlen($binary_string) % 40;
	switch ($padding_mod)
	{
		case 8 : $result = $result . str_repeat($base32_charset[32], 6); break;
		case 16: $result = $result . str_repeat($base32_charset[32], 4); break;
		case 24: $result = $result . str_repeat($base32_charset[32], 3); break;
		case 32: $result = $result . str_repeat($base32_charset[32], 1); break;
		default: $result = $result;                                      break;
	}

	return $result;
}



//Google Authenticator compatibility
function base32_decode($data)
{
	$result = '';
	$binary_string = '';
	$binary_string_chunks = '';
	
	$data = strtoupper($data);

	$base32_mapping = array(
								'A' => '0',  'B' => '1',  'C' => '2',  'D' => '3',  'E' => '4',  'F' => '5',  'G' => '6',  'H' => '7',
								'I' => '8',  'J' => '9',  'K' => '10', 'L' => '11', 'M' => '12', 'N' => '13', 'O' => '14', 'P' => '15',
								'Q' => '16', 'R' => '17', 'S' => '18', 'T' => '19', 'U' => '20', 'V' => '21', 'W' => '22', 'X' => '23',
								'Y' => '24', 'Z' => '25', '2' => '26', '3' => '27', '4' => '28', '5' => '29', '6' => '30', '7' => '31'
							);
	$base32_charset = array(
								'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L',	'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T',	'U', 'V', 'W', 'X',
								'Y', 'Z', '2', '3',	'4', '5', '6', '7',
								'='
							);

	$data = str_replace('=', '', $data);
	$data = str_split($data);

	for($counter = 0; $counter < count($data); $counter = $counter + 8)
	{
		$binary_string = '';
		for($counter_binary_string = 0; $counter_binary_string < 8; $counter_binary_string = $counter_binary_string + 1)
		{
			$binary_string = $binary_string . str_pad(base_convert($base32_mapping[$data[$counter + $counter_binary_string]], 10, 2), 5, '0', STR_PAD_LEFT);
		}
		$binary_string_chunks = str_split($binary_string, 8);
		for($counter_binary_string_chunks = 0; $counter_binary_string_chunks < count($binary_string_chunks); $counter_binary_string_chunks = $counter_binary_string_chunks + 1)
		{
			if (base_convert($binary_string_chunks[$counter_binary_string_chunks], 2, 10) != 0 )
			{
				$result = $result . chr(base_convert($binary_string_chunks[$counter_binary_string_chunks], 2, 10));
			}
			else
			{
				$result = $result . '';
			}
		}
	}

	return $result;
}



//generate binary data (counter for HOTP, time for TOTP)
function generate_hash_hmac_data($data)
{
	$result = '';
	
	if (isset($data))
	{
		$data_temp = '';
		$data_temp = str_pad(dechex($data), 16, '0', STR_PAD_LEFT);

		for ($counter = 0; $counter < (strlen($data_temp) / 2); $counter = $counter + 1)
		{
			$result = $result . chr(hexdec(substr($data_temp, ($counter * 2), 2)));
		}
	}
	else
	{
		//The counter of time data was a NULL string!
	}
	
	return $result;
}



//generate T value (for TOTP)
function generate_t_value($current_unix_time, $t_0, $time_step)
{
	$result = '';
	
	if (isset($current_unix_time) && isset($t_0) && isset($time_step))
	{
		$t = floor(($current_unix_time - $t_0) / $time_step);
		$result = $t;
	}
	else
	{
		//The current Unix time, initial time or time step (time slice, time window) was a NULL string!
	}

	return $result;
}



//generate hash_hmac with SHA-1, SHA-256 and SHA-512
function generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key)
{
	$result = '';
	
	if (($hash_hmac_algo == 'sha1') || ($hash_hmac_algo == 'sha256') || ($hash_hmac_algo == 'sha512'))
	{
		if (($hash_hmac_data != '') && ($hash_hmac_key != ''))
		{
			$result = hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key, TRUE);
		}
		else
		{
			//The shared secret key of data-to-be-hashed was a NULL string!
		}
	}
	else
	{
		//Not supported hash algorithm!
	}
	
	return $result;
}



//generate truncated value hash
function generate_truncated_value($data, $hash_hmac_algo)
{
	$result = '';
	
	if ($data != '')
	{
		switch ($hash_hmac_algo)
		{
			case 'sha1'  : $counter_algo = 19; break;
			case 'sha256': $counter_algo = 31; break;
			case 'sha512': $counter_algo = 63; break;
			default      : $counter_algo = 19; break;
		}

		//processing the result of hash_hmac
		$truncate_offset_bits = '';
		$truncate_offset_bits = decbin(ord($data[$counter_algo]));

		//padding final byte with "0" values to 8 bits (string)
		while (strlen($truncate_offset_bits) < 8)
		{
			$truncate_offset_bits = '0' . $truncate_offset_bits;
		}

		//selecting the final 4 bits to compute offset
		$truncate_offset_bits_temp = '';
		for ($counter = 4; $counter < 8; $counter = $counter + 1)
		{
			$truncate_offset_bits_temp = $truncate_offset_bits_temp . $truncate_offset_bits[$counter];
		}
		$truncate_offset_bits = bindec($truncate_offset_bits_temp);

		//selecting bytes of the hash from the offset 
		$counter = 0;
		$truncate_offset_data_temp = '';
		for ($counter = $truncate_offset_bits; $counter < ($truncate_offset_bits + 4); $counter = $counter + 1)
		{
			$truncate_offset_data_temp = $truncate_offset_data_temp . str_pad(dechex(ord($data[$counter])), 2, '0', STR_PAD_LEFT);
		}
		$truncate_offset_data = decbin(hexdec($truncate_offset_data_temp));

		//padding final byte with "0" values to 32 bits (string)
		while (strlen($truncate_offset_data) < 32)
		{
			$truncate_offset_data = '0' . $truncate_offset_data;
		}

		//selecting the final 31 bits
		$counter = 0;
		$truncate_offset_data_temp = '';
		while ($counter < 32)
		{
			if ($counter > 0)
			{
				$truncate_offset_data_temp = $truncate_offset_data_temp . $truncate_offset_data[$counter];
			}
			$counter = $counter + 1;
		}
		$result = bindec($truncate_offset_data_temp);
	}
	else
	{
		//The data-to-be-truncated was a NULL string!
	}

	return $result;
}



//generate response based on challenge
function generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp)
{
	$result = array();
	$ocra_suite_length = strlen($ocra_suite);
	$counter_length = 0;
	$question_length = 0;
	$password_length = 0;
	$session_information_length = 0;
	$timestamp_length = 0;
 
	$digits = 0;
	$hash_hmac_algo = '';
	$hash_hmac_data = '';
	$hash_hmac_key = '';

	$data_input_array = array();
	list($algorithm, $crypto_function, $data_input) = explode(':', $ocra_suite);
	list($crypto_function_mode, $crypto_function_hash, $crypto_function_length) = explode('-', $crypto_function);
	$data_input_array = explode('-', $data_input);

	switch($crypto_function_hash)
	{
		case 'SHA1'  : $hash_hmac_algo = 'sha1';   break;
		case 'SHA256': $hash_hmac_algo = 'sha256'; break;
		case 'SHA512': $hash_hmac_algo = 'sha512'; break;
		default      : $hash_hmac_algo = 'sha256'; break;
	}
 
	$digits = (int)$crypto_function_length;

	if (substr($data_input_array[0], 0, 1) == 'C')
	{
		while (strlen($counter) < 16)
		{
			$counter = '0' . (string)$counter;
		}
	$counter_length = 8;
	}

	if ((substr($data_input_array[0], 0, 2) == 'QN') || (substr($data_input_array[1], 0, 2) == 'QN'))
	{
		$question_value = '';
		$question_value = dechex($question);
		while (strlen($question_value) < 256)
		{
			$question_value = $question_value . '0';
		}
		$question = $question_value;
		$question_length = 128;
	}

	if ((substr($data_input_array[0], 0, 2) == 'QA') || (substr($data_input_array[1], 0, 2) == 'QA'))
	{
		$question_value = '';
		$question_value = convert_to_hex($question);
		while (strlen($question_value) < 256)
		{
			$question_value = $question_value . '0';
		}
		$question = $question_value;
		$question_length = 128;
	}
  
	if ((substr($data_input_array[0], 0, 5) == 'PSHA1') || (substr($data_input_array[1], 0, 5) == 'PSHA1') || (substr($data_input_array[2], 0, 5) == 'PSHA1'))
	{
		$password_hash = '';
		$password_hash = convert_to_hex(hash('sha1', $password, TRUE));
		while (strlen($password_hash) < 40)
		{
			$password_hash = '0' . $password_hash;
		}
		$password = $password_hash;
		$password_length = 20;
	}
  
	if ((substr($data_input_array[0], 0, 7) == 'PSHA256') || (substr($data_input_array[1], 0, 7) == 'PSHA256') || (substr($data_input_array[2], 0, 7) == 'PSHA256'))
	{
		$password_hash = '';
		$password_hash = convert_to_hex(hash('sha256', $password, TRUE));
		while (strlen($password_hash) < 64)
		{
			$password_hash = '0' . $password_hash;
		}
		$password = $password_hash;
		$password_length = 32;
	}
  
	if ((substr($data_input_array[0], 0, 7) == 'PSHA512') || (substr($data_input_array[1], 0, 7) == 'PSHA512') || (substr($data_input_array[2], 0, 7) == 'PSHA512'))
	{
		$password_hash = '';
		$password_hash = convert_to_hex(hash('sha512', $password, TRUE));
		while (strlen($password_hash) < 128)
		{
			$password_hash = '0' . $password_hash;
		}
		$password = $password_hash;
		$password_length = 64;
	}
  
	if ((substr($data_input_array[0], 0, 4) == 'S064') || (substr($data_input_array[1], 0, 4) == 'S064') || (substr($data_input_array[2], 0, 4) == 'S064'))
	{
		while (strlen($session_information) < 128)
		{
			$session_information = '0' . $session_information;
		}
		$session_information_length = 64;
	}
  
	if ((substr($data_input_array[0], 0, 4) == 'S128') || (substr($data_input_array[1], 0, 4) == 'S128') || (substr($data_input_array[2], 0, 4) == 'S128'))
	{
		while (strlen($session_information) < 256)
		{
		$session_information = '0' . $session_information;
		}
		$session_information_length = 128;
	}
  
	if ((substr($data_input_array[0], 0, 4) == 'S256') || (substr($data_input_array[1], 0, 4) == 'S256') || (substr($data_input_array[2], 0, 4) == 'S256'))
	{
		while (strlen($session_information) < 512)
		{
			$session_information = '0' . $session_information;
		}
		$session_information_length = 256;
	}
 
	if ((substr($data_input_array[0], 0, 4) == 'S512') || (substr($data_input_array[1], 0, 4) == 'S512') || (substr($data_input_array[2], 0, 4) == 'S512'))
	{
		while (strlen($session_information) < 1024)
		{
			$session_information = '0' . $session_information;
		}
		$session_information_length = 512;
	}
  
	if ((substr($data_input_array[0], 0, 1) == 'T') || (substr($data_input_array[1], 0, 1) == 'T') || (substr($data_input_array[2], 0, 1) == 'T'))
	{
		while (strlen($timestamp) < 16)
		{
			$timestamp = '0' . $timestamp;
		}
		$timestamp_length = 8;
	}

	if (strlen($ocra_suite) > 0)
	{
		$hash_hmac_data = $hash_hmac_data . $ocra_suite;
		$hash_hmac_data = $hash_hmac_data . convert_to_character('00');
	}

	if ($counter_length > 0)
	{
		$hash_hmac_data = $hash_hmac_data . convert_to_character($counter);
	}

	if ($question_length > 0)
	{
		$hash_hmac_data = $hash_hmac_data . convert_to_character($question);
	}

	if ($password_length > 0)
	{
		$hash_hmac_data = $hash_hmac_data . convert_to_character($password);
	}

	if ($session_information_length > 0)
	{
		$hash_hmac_data = $hash_hmac_data . convert_to_character($session_information);
	}

	if ($timestamp_length > 0)
	{
		$hash_hmac_data = $hash_hmac_data . convert_to_character($timestamp);
	}

	if (strlen($key) > 0)
	{
		$hash_hmac_key = $key;

		$result[0] = $hash_hmac_algo;
		$result[1] = $hash_hmac_data;
		$result[2] = $hash_hmac_key;
		$result[3] = $digits;
	}

	return $result;
}



//generate HOTP or TOTP data
function generate_HOTP_TOTP_value($data, $digits)
{
	$result = '';
	
	if (is_int($digits) && ($data != ''))
	{
		if ($digits > 5)
		{
			$divided_by = pow(10, $digits);

			//compute modulus (HOTP or TOTP value) in the given length (digits)
			$result = $data % $divided_by;

			//padding one-time-password with "0" values to given number of digits (string)
			while (strlen($result) < $digits)
			{
				$result = '0' . $result;
			}
		}
		else
		{
			//The number of digits must be at least 6, value 7 and 8 must be also supported based on RFC requirements!
		}
	}
	else
	{
		//The exponent or the truncated data was a NULL string!
	}
	
	return $result;
 }



//perform self-test based on given input-output data pairs of RFC 4226 and RFC 6238
function perform_self_test()
	{
	//IETF RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm
	$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc4226.txt" target="_blank"><b>IETF RFC 4226</b></a> - Appendix D - HOTP Algorithm: Test Values<br/><br/>';
	$html_body = $html_body . '<table><tr><td><b>Count</b></td><td><b>Hexadecimal HMAC-SHA-1(secret, count)</b></td><td><b>HOTP</b></td></tr>';

	//counter = 0..9
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = 'sha1';
	$hash_hmac_test[0][1] = 0;
	$hash_hmac_test[0][2] = '12345678901234567890';
	$hash_hmac_test[1][0] = 'sha1';
	$hash_hmac_test[1][1] = 1;
	$hash_hmac_test[1][2] = '12345678901234567890';
	$hash_hmac_test[2][0] = 'sha1';
	$hash_hmac_test[2][1] = 2;
	$hash_hmac_test[2][2] = '12345678901234567890';
	$hash_hmac_test[3][0] = 'sha1';
	$hash_hmac_test[3][1] = 3;
	$hash_hmac_test[3][2] = '12345678901234567890';
	$hash_hmac_test[4][0] = 'sha1';
	$hash_hmac_test[4][1] = 4;
	$hash_hmac_test[4][2] = '12345678901234567890';
	$hash_hmac_test[5][0] = 'sha1';
	$hash_hmac_test[5][1] = 5;
	$hash_hmac_test[5][2] = '12345678901234567890';
	$hash_hmac_test[6][0] = 'sha1';
	$hash_hmac_test[6][1] = 6;
	$hash_hmac_test[6][2] = '12345678901234567890';
	$hash_hmac_test[7][0] = 'sha1';
	$hash_hmac_test[7][1] = 7;
	$hash_hmac_test[7][2] = '12345678901234567890';
	$hash_hmac_test[8][0] = 'sha1';
	$hash_hmac_test[8][1] = 8;
	$hash_hmac_test[8][2] = '12345678901234567890';
	$hash_hmac_test[9][0] = 'sha1';
	$hash_hmac_test[9][1] = 9;
	$hash_hmac_test[9][2] = '12345678901234567890';

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$hash_hmac_algo = $hash_hmac_test[$counter_hash_hmac][0];
		$hash_hmac_data_chr = $hash_hmac_test[$counter_hash_hmac][1];
		$hash_hmac_key = $hash_hmac_test[$counter_hash_hmac][2];

		$digits = 6;

		$hash_hmac_data = generate_hash_hmac_data($hash_hmac_data_chr);
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);

		$hash_hmac_string = '';
		for ($counter = 0; $counter < 20; $counter = $counter + 1)
		{
			$hash_hmac_string = $hash_hmac_string . str_pad(dechex(ord($hash_hmac[$counter])), 2, '0', STR_PAD_LEFT);
		}
		$html_body = $html_body . '<tr><td>' . $hash_hmac_data_chr . '</td><td>' . $hash_hmac_string . '</td><td>' . $otp . '</td></tr>';
	}
	$html_body = $html_body . '</table>';

	//IETF RFC 6238 - TOTP: Time-Based One-Time Password Algorithm
	$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc6238.txt" target="_blank"><b>IETF RFC 6238</b></a> - Appendix B.  Test Vectors<br/><br/>';
	$html_body = $html_body . '<table><tr><td><b>Time (sec)</b></td><td><b>UTC Time</b></td><td><b>Value of T (hex)</b></td><td><b>TOTP</b></td><td><b>Mode</b></td></tr>';

	//Unix time = 59..1234567890..20000000000
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = 'sha1';
	$hash_hmac_test[0][1] = 59;
	$hash_hmac_test[0][2] = '12345678901234567890';
	$hash_hmac_test[1][0] = 'sha256';
	$hash_hmac_test[1][1] = 59;
	$hash_hmac_test[1][2] = '12345678901234567890123456789012';
	$hash_hmac_test[2][0] = 'sha512';
	$hash_hmac_test[2][1] = 59;
	$hash_hmac_test[2][2] = '1234567890123456789012345678901234567890123456789012345678901234';
	$hash_hmac_test[3][0] = 'sha1';
	$hash_hmac_test[3][1] = 1111111109;
	$hash_hmac_test[3][2] = '12345678901234567890';
	$hash_hmac_test[4][0] = 'sha256';
	$hash_hmac_test[4][1] = 1111111109;
	$hash_hmac_test[4][2] = '12345678901234567890123456789012';
	$hash_hmac_test[5][0] = 'sha512';
	$hash_hmac_test[5][1] = 1111111109;
	$hash_hmac_test[5][2] = '1234567890123456789012345678901234567890123456789012345678901234';
	$hash_hmac_test[6][0] = 'sha1';
	$hash_hmac_test[6][1] = 1111111111;
	$hash_hmac_test[6][2] = '12345678901234567890';
	$hash_hmac_test[7][0] = 'sha256';
	$hash_hmac_test[7][1] = 1111111111;
	$hash_hmac_test[7][2] = '12345678901234567890123456789012';
	$hash_hmac_test[8][0] = 'sha512';
	$hash_hmac_test[8][1] = 1111111111;
	$hash_hmac_test[8][2] = '1234567890123456789012345678901234567890123456789012345678901234';
	$hash_hmac_test[9][0] = 'sha1';
	$hash_hmac_test[9][1] = 1234567890;
	$hash_hmac_test[9][2] = '12345678901234567890';
	$hash_hmac_test[10][0] = 'sha256';
	$hash_hmac_test[10][1] = 1234567890;
	$hash_hmac_test[10][2] = '12345678901234567890123456789012';
	$hash_hmac_test[11][0] = 'sha512';
	$hash_hmac_test[11][1] = 1234567890;
	$hash_hmac_test[11][2] = '1234567890123456789012345678901234567890123456789012345678901234';
	$hash_hmac_test[12][0] = 'sha1';
	$hash_hmac_test[12][1] = 2000000000;
	$hash_hmac_test[12][2] = '12345678901234567890';
	$hash_hmac_test[13][0] = 'sha256';
	$hash_hmac_test[13][1] = 2000000000;
	$hash_hmac_test[13][2] = '12345678901234567890123456789012';
	$hash_hmac_test[14][0] = 'sha512';
	$hash_hmac_test[14][1] = 2000000000;
	$hash_hmac_test[14][2] = '1234567890123456789012345678901234567890123456789012345678901234';
	$hash_hmac_test[15][0] = 'sha1';
	$hash_hmac_test[15][1] = 20000000000;
	$hash_hmac_test[15][2] = '12345678901234567890';
	$hash_hmac_test[16][0] = 'sha256';
	$hash_hmac_test[16][1] = 20000000000;
	$hash_hmac_test[16][2] = '12345678901234567890123456789012';
	$hash_hmac_test[17][0] = 'sha512';
	$hash_hmac_test[17][1] = 20000000000;
	$hash_hmac_test[17][2] = '1234567890123456789012345678901234567890123456789012345678901234';

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$hash_hmac_algo = $hash_hmac_test[$counter_hash_hmac][0];
		$hash_hmac_data_chr = $hash_hmac_test[$counter_hash_hmac][1];
		$hash_hmac_key = $hash_hmac_test[$counter_hash_hmac][2];

		$digits = 8;

		$current_unix_time = $hash_hmac_data_chr;
		$t_0 = 0;
		$time_step = 30;
		$t = generate_t_value($current_unix_time, $t_0, $time_step);
		$t = str_pad(dechex($t), 16, '0', STR_PAD_LEFT);

		$hash_hmac_data_chr = hexdec($t);
		$hash_hmac_data = generate_hash_hmac_data($hash_hmac_data_chr);
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);

		$hash_hmac_string = '';
		for ($counter = 0; $counter < 20; $counter = $counter + 1)
		{
			$hash_hmac_string = $hash_hmac_string . str_pad(dechex(ord($hash_hmac[$counter])), 2, '0', STR_PAD_LEFT);
		}
		$date = new DateTime('@' . $current_unix_time);
		$html_body = $html_body . '<tr><td>' . $current_unix_time . '</td><td>' . $date->format('Y-m-d H:i:s') . '</td><td>' . $t . '</td><td>' . $otp . '</td><td>' . $hash_hmac_algo . '</td></tr>';
	}
	$html_body = $html_body . '</table>';

	//IETF RFC 6287 - OCRA: OATH Challenge-Response Algorithm
	$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc6287.txt" target="_blank"><b>IETF RFC 6287</b></a> - Appendix C.  Test Vectors<br/><br/>';
	$html_body = $html_body . '<table><tr><td><b>Key</b></td><td><b>OCRASuite</b></td><td><b>Counter</b></td><td><b>Question</b></td><td><b>Password</b></td><td><b>Session Information</b></td><td><b>Timestamp</b></td><td><b>OCRA</b></td></tr>';

	//OCRA-1:HOTP-SHA1-6:QN08
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = '00000000';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = '11111111';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = '22222222';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = '33333333';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = '44444444';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');
	$hash_hmac_test[5][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[5][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[5][2] = null;
	$hash_hmac_test[5][3] = '55555555';
	$hash_hmac_test[5][4] = '1234';
	$hash_hmac_test[5][5] = convert_to_hex('');
	$hash_hmac_test[5][6] = dechex('');
	$hash_hmac_test[6][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[6][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[6][2] = null;
	$hash_hmac_test[6][3] = '66666666';
	$hash_hmac_test[6][4] = '1234';
	$hash_hmac_test[6][5] = convert_to_hex('');
	$hash_hmac_test[6][6] = dechex('');
	$hash_hmac_test[7][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[7][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[7][2] = null;
	$hash_hmac_test[7][3] = '77777777';
	$hash_hmac_test[7][4] = '1234';
	$hash_hmac_test[7][5] = convert_to_hex('');
	$hash_hmac_test[7][6] = dechex('');
	$hash_hmac_test[8][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[8][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[8][2] = null;
	$hash_hmac_test[8][3] = '88888888';
	$hash_hmac_test[8][4] = '1234';
	$hash_hmac_test[8][5] = convert_to_hex('');
	$hash_hmac_test[8][6] = dechex('');
	$hash_hmac_test[9][0] = convert_to_character('3132333435363738393031323334353637383930');
	$hash_hmac_test[9][1] = strtoupper('OCRA-1:HOTP-SHA1-6:QN08'); 
	$hash_hmac_test[9][2] = null;
	$hash_hmac_test[9][3] = '99999999';
	$hash_hmac_test[9][4] = '1234';
	$hash_hmac_test[9][5] = convert_to_hex('');
	$hash_hmac_test[9][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[0][2] = 0;
	$hash_hmac_test[0][3] = '12345678';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[1][2] = 1;
	$hash_hmac_test[1][3] = '12345678';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[2][2] = 2;
	$hash_hmac_test[2][3] = '12345678';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[3][2] = 3;
	$hash_hmac_test[3][3] = '12345678';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[4][2] = 4;
	$hash_hmac_test[4][3] = '12345678';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');
	$hash_hmac_test[5][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[5][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[5][2] = 5;
	$hash_hmac_test[5][3] = '12345678';
	$hash_hmac_test[5][4] = '1234';
	$hash_hmac_test[5][5] = convert_to_hex('');
	$hash_hmac_test[5][6] = dechex('');
	$hash_hmac_test[6][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[6][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[6][2] = 6;
	$hash_hmac_test[6][3] = '12345678';
	$hash_hmac_test[6][4] = '1234';
	$hash_hmac_test[6][5] = convert_to_hex('');
	$hash_hmac_test[6][6] = dechex('');
	$hash_hmac_test[7][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[7][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[7][2] = 7;
	$hash_hmac_test[7][3] = '12345678';
	$hash_hmac_test[7][4] = '1234';
	$hash_hmac_test[7][5] = convert_to_hex('');
	$hash_hmac_test[7][6] = dechex('');
	$hash_hmac_test[8][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[8][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[8][2] = 8;
	$hash_hmac_test[8][3] = '12345678';
	$hash_hmac_test[8][4] = '1234';
	$hash_hmac_test[8][5] = convert_to_hex('');
	$hash_hmac_test[8][6] = dechex('');
	$hash_hmac_test[9][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[9][1] = strtoupper('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1'); 
	$hash_hmac_test[9][2] = 9;
	$hash_hmac_test[9][3] = '12345678';
	$hash_hmac_test[9][4] = '1234';
	$hash_hmac_test[9][5] = convert_to_hex('');
	$hash_hmac_test[9][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//OCRA-1:HOTP-SHA256-8:QN08-PSHA1
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QN08-PSHA1'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = '00000000';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QN08-PSHA1'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = '11111111';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QN08-PSHA1'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = '22222222';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QN08-PSHA1'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = '33333333';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QN08-PSHA1'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = '44444444';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//OCRA-1:HOTP-SHA512-8:C-QN08
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[0][2] = 0;
	$hash_hmac_test[0][3] = '00000000';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[1][2] = 1;
	$hash_hmac_test[1][3] = '11111111';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[2][2] = 2;
	$hash_hmac_test[2][3] = '22222222';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[3][2] = 3;
	$hash_hmac_test[3][3] = '33333333';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[4][2] = 4;
	$hash_hmac_test[4][3] = '44444444';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');
	$hash_hmac_test[5][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[5][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[5][2] = 5;
	$hash_hmac_test[5][3] = '55555555';
	$hash_hmac_test[5][4] = '1234';
	$hash_hmac_test[5][5] = convert_to_hex('');
	$hash_hmac_test[5][6] = dechex('');
	$hash_hmac_test[6][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[6][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[6][2] = 6;
	$hash_hmac_test[6][3] = '66666666';
	$hash_hmac_test[6][4] = '1234';
	$hash_hmac_test[6][5] = convert_to_hex('');
	$hash_hmac_test[6][6] = dechex('');
	$hash_hmac_test[7][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[7][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[7][2] = 7;
	$hash_hmac_test[7][3] = '77777777';
	$hash_hmac_test[7][4] = '1234';
	$hash_hmac_test[7][5] = convert_to_hex('');
	$hash_hmac_test[7][6] = dechex('');
	$hash_hmac_test[8][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[8][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[8][2] = 8;
	$hash_hmac_test[8][3] = '88888888';
	$hash_hmac_test[8][4] = '1234';
	$hash_hmac_test[8][5] = convert_to_hex('');
	$hash_hmac_test[8][6] = dechex('');
	$hash_hmac_test[9][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[9][1] = strtoupper('OCRA-1:HOTP-SHA512-8:C-QN08'); 
	$hash_hmac_test[9][2] = 9;
	$hash_hmac_test[9][3] = '99999999';
	$hash_hmac_test[9][4] = '1234';
	$hash_hmac_test[9][5] = convert_to_hex('');
	$hash_hmac_test[9][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//OCRA-1:HOTP-SHA512-8:QN08-T1M
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QN08-T1M'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = '00000000';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[1][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QN08-T1M'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = '11111111';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[2][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QN08-T1M'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = '22222222';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[3][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QN08-T1M'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = '33333333';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[4][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QN08-T1M'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = '44444444';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//Client -- OCRA-1:HOTP-SHA256-8:QA08
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = 'CLI22220SRV11110';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = 'CLI22221SRV11111';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = 'CLI22222SRV11112';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = 'CLI22223SRV11113';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = 'CLI22224SRV11114';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//Server -- OCRA-1:HOTP-SHA256-8:QA08
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = 'SRV11110CLI22220';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = 'SRV11111CLI22221';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = 'SRV11112CLI22222';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = 'SRV11113CLI22223';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = 'SRV11114CLI22224';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//Client -- OCRA-1:HOTP-SHA512-8:QA08
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = 'CLI22220SRV11110';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = 'CLI22221SRV11111';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = 'CLI22222SRV11112';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = 'CLI22223SRV11113';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = 'CLI22224SRV11114';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//Server -- OCRA-1:HOTP-SHA512-8:QA08-PSHA1
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08-PSHA1'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = 'SRV11110CLI22220';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08-PSHA1'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = 'SRV11111CLI22221';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08-PSHA1'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = 'SRV11112CLI22222';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08-PSHA1'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = 'SRV11113CLI22223';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA08-PSHA1'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = 'SRV11114CLI22224';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//OCRA-1:HOTP-SHA256-8:QA08
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = 'SIG10000';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('');
	$hash_hmac_test[1][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = 'SIG11000';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('');
	$hash_hmac_test[2][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = 'SIG12000';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('');
	$hash_hmac_test[3][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = 'SIG13000';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('');
	$hash_hmac_test[4][0] = convert_to_character('3132333435363738393031323334353637383930313233343536373839303132');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA256-8:QA08'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = 'SIG14000';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('');

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//OCRA-1:HOTP-SHA512-8:QA10-T1M
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA10-T1M'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = 'SIG1000000';
	$hash_hmac_test[0][4] = '1234';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[1][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[1][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA10-T1M'); 
	$hash_hmac_test[1][2] = null;
	$hash_hmac_test[1][3] = 'SIG1100000';
	$hash_hmac_test[1][4] = '1234';
	$hash_hmac_test[1][5] = convert_to_hex('');
	$hash_hmac_test[1][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[2][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[2][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA10-T1M'); 
	$hash_hmac_test[2][2] = null;
	$hash_hmac_test[2][3] = 'SIG1200000';
	$hash_hmac_test[2][4] = '1234';
	$hash_hmac_test[2][5] = convert_to_hex('');
	$hash_hmac_test[2][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[3][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[3][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA10-T1M'); 
	$hash_hmac_test[3][2] = null;
	$hash_hmac_test[3][3] = 'SIG1300000';
	$hash_hmac_test[3][4] = '1234';
	$hash_hmac_test[3][5] = convert_to_hex('');
	$hash_hmac_test[3][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
	$hash_hmac_test[4][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[4][1] = strtoupper('OCRA-1:HOTP-SHA512-8:QA10-T1M'); 
	$hash_hmac_test[4][2] = null;
	$hash_hmac_test[4][3] = 'SIG1400000';
	$hash_hmac_test[4][4] = '1234';
	$hash_hmac_test[4][5] = convert_to_hex('');
	$hash_hmac_test[4][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.

	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//ARON - OCRA-1:HOTP-SHA512-10:QN10-PSHA512-T1M
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA512-10:QN10-PSHA512-T1M'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = '1111111111';
	$hash_hmac_test[0][4] = 'dead00beef';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp. 
  
	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}

	//ARON - OCRA-1:HOTP-SHA512-10:QA10-PSHA512-T1M
	$hash_hmac_test = array();
	$hash_hmac_test[0][0] = convert_to_character('31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334');
	$hash_hmac_test[0][1] = strtoupper('OCRA-1:HOTP-SHA512-10:QA10-PSHA512-T1M'); 
	$hash_hmac_test[0][2] = null;
	$hash_hmac_test[0][3] = 'SIG1000000';
	$hash_hmac_test[0][4] = 'dead00beef';
	$hash_hmac_test[0][5] = convert_to_hex('');
	$hash_hmac_test[0][6] = dechex('20107446'); //This is the decimal value of 132d0b6 timestamp.
  
	for ($counter_hash_hmac = 0; $counter_hash_hmac < count($hash_hmac_test); $counter_hash_hmac = $counter_hash_hmac + 1)
	{
		$key = $hash_hmac_test[$counter_hash_hmac][0];
		$ocra_suite = $hash_hmac_test[$counter_hash_hmac][1];
		$counter = $hash_hmac_test[$counter_hash_hmac][2];
		$question = $hash_hmac_test[$counter_hash_hmac][3];
		$password = $hash_hmac_test[$counter_hash_hmac][4];
		$session_information = $hash_hmac_test[$counter_hash_hmac][5];
		$timestamp = $hash_hmac_test[$counter_hash_hmac][6];

		$hash_hmac_data_ocra = array();
		$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
		$hash_hmac_algo = $hash_hmac_data_ocra[0];
		$hash_hmac_data = $hash_hmac_data_ocra[1];
		$hash_hmac_key = $hash_hmac_data_ocra[2];
		$digits = $hash_hmac_data_ocra[3];
		$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
		$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
		$otp = generate_HOTP_TOTP_value($truncated_data, $digits);
		$html_body = $html_body . '<tr><td>' . 'Standard ' . strlen($hash_hmac_test[$counter_hash_hmac][0]) . 'Byte' . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][1] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][2] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][3] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][4] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][5] . '</td><td>' . $hash_hmac_test[$counter_hash_hmac][6] . '</td><td>' . $otp . '</td></tr>';
	}
	$html_body = $html_body . "</table>";

	return  $html_body;
}



//HTTP POST variables
function post_method_url($http_data, $url_data, $proxy_data)
{
	$result = '';
	$http = $http_data;
	$url = $url_data;
	$proxy = $proxy_data;

	$cURL = curl_init();
	curl_setopt($cURL, CURLOPT_POST, TRUE);
	curl_setopt($cURL, CURLOPT_URL, $url);
	curl_setopt($cURL, CURLOPT_SSL_VERIFYPEER, FALSE);
	curl_setopt($cURL, CURLOPT_SSL_VERIFYHOST, FALSE);
	curl_setopt($cURL, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($cURL, CURLOPT_VERBOSE, TRUE);
	curl_setopt($cURL, CURLOPT_FOLLOWLOCATION, TRUE);
	curl_setopt($cURL, CURLOPT_POSTFIELDS, http_build_query($http));
	curl_setopt($cURL, CURLOPT_PROXY, $proxy);
	$http = curl_exec($cURL);
	$result = curl_getinfo($cURL);
	$result['content'] = $http;
	curl_close($cURL);

	return $result;
}



//HTTP GET variables
function get_method_url($url_data, $proxy_data)
{
	$result = '';
	$http = '';
	$url = $url_data;
	$proxy = $proxy_data;

	$cURL = curl_init();
	curl_setopt($cURL, CURLOPT_HTTPGET, TRUE);
	curl_setopt($cURL, CURLOPT_URL, $url);
	curl_setopt($cURL, CURLOPT_SSL_VERIFYPEER, FALSE);
	curl_setopt($cURL, CURLOPT_SSL_VERIFYHOST, FALSE);
	curl_setopt($cURL, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($cURL, CURLOPT_VERBOSE, TRUE);
	curl_setopt($cURL, CURLOPT_FOLLOWLOCATION, TRUE);
	curl_setopt($cURL, CURLOPT_PROXY, $proxy);
	$http = curl_exec($cURL);
	$result = curl_getinfo($cURL);
	$result['content'] = $http;
	curl_close($cURL);

	return $result;
}



//creating base string of data-to-be-signed for OAuth 1.0a
function create_string_merge($data, $oauth_callback, $oauth_consumer_key, $oauth_nonce, $oauth_signature_method, $oauth_timestamp, $oauth_token, $oauth_verifier, $oauth_version)
{ 
	$string_merge = '';
	$string_merge = $string_merge . 'data=' . rawurlencode(utf8_encode($data));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_callback' . '=' . rawurlencode(utf8_encode($oauth_callback));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_consumer_key' . '=' . rawurlencode(utf8_encode($oauth_consumer_key));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_nonce' . '=' . rawurlencode(utf8_encode($oauth_nonce));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_signature_method' . '=' . rawurlencode(utf8_encode($oauth_signature_method));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_timestamp' . '=' . rawurlencode(utf8_encode($oauth_timestamp));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_token' . '=' . rawurlencode(utf8_encode($oauth_token));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_verifier' . '=' . rawurlencode(utf8_encode($oauth_verifier));
	$string_merge = $string_merge . '&';
	$string_merge = $string_merge . 'oauth_version' . '=' . rawurlencode(utf8_encode($oauth_version));

	return $string_merge;
}



//creating data-to-be-signed for OAuth 1.0a
function create_string($base_url, $string_merge)
{ 
	$string = '';
	$string = $string . 'GET';
	$string = $string . '&';
	$string = $string . rawurlencode($base_url);
	$string = $string . '&';
	$string = $string . rawurlencode($string_merge);

	return $string;
}



//creating signature value for OAuth 1.0a
function create_oauth_signature($oauth_signature_method, $oauth_consumer_secret, $oauth_token_secret, $string, $oauth_private_key)
{
	if ($oauth_signature_method == 'HMAC-SHA1')
	{
		$hash_hmac_algo = 'sha1';
		$hash_hmac_data = $string;
		$hash_hmac_key = rawurlencode($oauth_consumer_secret) . '&' . rawurlencode($oauth_token_secret);
		$oauth_signature = rawurlencode(base64_encode(generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key)));
	}
	if ($oauth_signature_method == 'PLAINTEXT')
	{
		$hash_plaintext_key = rawurlencode($oauth_consumer_secret) . '&' . rawurlencode($oauth_token_secret);
		//perhaps it is a bug of term.ie public test server: rawurlencode() should be performed just once, not twice!
		$oauth_signature = rawurlencode(rawurlencode($hash_plaintext_key));
	}
	if ($oauth_signature_method == 'RSA-SHA1')
	{
		$hash_pkcs1_algo = 'sha1';
		$hash_pkcs1_data = $string;
		$hash_pkcs1_key = openssl_pkey_get_private($oauth_private_key);
		openssl_sign($hash_pkcs1_data, $hash_pkcs1_signature, $hash_pkcs1_key, $hash_pkcs1_algo);
		openssl_free_key($hash_pkcs1_key);
		$oauth_signature = rawurlencode(base64_encode($hash_pkcs1_signature));
	}

	return $oauth_signature;
}



//parsing responses of OAuth 1.0a requests
function parse_response($response)
{
	$variable_pairs = array();
	$parameters = explode('&', $response['content']);
	
	for ($counter = 0; $counter < count($parameters); $counter = $counter + 1)
	{
		list($variable_names[$counter], $variable_values[$counter]) = explode('=', $parameters[$counter]);
		$variable_pairs[$variable_names[$counter]] = $variable_values[$counter];
	}

	return $variable_pairs;
}



//////
//MAIN
//////



date_default_timezone_set('UTC');
if ((is_numeric($_POST['hotp_data'])) && ($_POST['hotp_key'] != '') && ($_POST['hotp_algo'] == ('sha1'||'sha256'||'sha512')) && (is_numeric($_POST['hotp_digits'])))
{
	$hash_hmac_algo = $_POST['hotp_algo'];
	$hash_hmac_data_chr = 0 + $_POST['hotp_data'];
	$hash_hmac_key = $_POST['hotp_key'];
	$digits = 0 + $_POST['hotp_digits'];

	$hash_hmac_data = generate_hash_hmac_data($hash_hmac_data_chr);
	$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
	$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
	$otp = generate_HOTP_TOTP_value($truncated_data, $digits);

	echo '<br/><b>HOTP (RFC 4226), TOTP (RFC 6238), OCRA (RFC 6287) and OAuth 1.0a (RFC 5849), OAuth 2.0 (RFC 6749) test application</b><br/>HOTP one-time-password: <b>' . $otp . '</b><br/><br/><br/>';
	echo '<table align="justify" border="1" width="100%"><tr><td width="50%">';
	echo '<b>request:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr></table>';

}
elseif ((is_numeric($_POST['totp_data'])) && ($_POST['totp_key'] != '') && ($_POST['totp_algo'] == ('sha1'||'sha256'||'sha512')) && (is_numeric($_POST['totp_digits'])) && (is_numeric($_POST['totp_time_step'])) && (is_numeric($_POST['totp_step_time_window'])) && (is_numeric($_POST['totp_time_initial'])))
{
	$hash_hmac_algo = $_POST['totp_algo'];
	$hash_hmac_data_chr = 0 + $_POST['totp_data'];
	$hash_hmac_key = $_POST['totp_key'];
	$digits = 0 + $_POST['totp_digits'];

	$current_unix_time = $hash_hmac_data_chr;
	$t_0 = 0 + $_POST['totp_time_initial'];
	$time_step = 0 + $_POST['totp_time_step'];
	$time_step_window = 0 + $_POST['totp_time_step_window'];
	$t = generate_t_value($current_unix_time, $t_0, $time_step);
	$t = str_pad(dechex($t), 16, '0', STR_PAD_LEFT);
	$hash_hmac_data_chr = hexdec($t);
	$hash_hmac_data = generate_hash_hmac_data($hash_hmac_data_chr);
	$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
	$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
	$otp = generate_HOTP_TOTP_value($truncated_data, $digits);

	echo '<br/><b>HOTP (RFC 4226), TOTP (RFC 6238), OCRA (RFC 6287) and OAuth 1.0a (RFC 5849), OAuth 2.0 (RFC 6749) test application</b><br/>TOTP one-time-password: <b>' . $otp . '</b><br/><br/><br/>';
	echo '<table align="justify" border="1" width="100%"><tr><td width="50%">';
	echo '<b>request:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr></table>';
 
}
elseif ((is_numeric($_POST['google_totp_data'])) && ($_POST['google_totp_key'] != '') && ($_POST['google_totp_algo'] == ('sha1'||'sha256'||'sha512')) && (is_numeric($_POST['google_totp_digits'])) && (is_numeric($_POST['google_totp_time_step'])) && (is_numeric($_POST['google_totp_step_time_window'])) && (is_numeric($_POST['google_totp_time_initial'])))
{
	$hash_hmac_algo = $_POST['google_totp_algo'];
	$hash_hmac_data_chr = 0 + $_POST['google_totp_data'];
	$hash_hmac_key = base32_decode($_POST['google_totp_key']);
	$digits = 0 + $_POST['google_totp_digits'];

	$current_unix_time = $hash_hmac_data_chr;
	$t_0 = 0 + $_POST['google_totp_time_initial'];
	$time_step = 0 + $_POST['google_totp_time_step'];
	$time_step_window = 0 + $_POST['google_totp_time_step_window'];
	$t = generate_t_value($current_unix_time, $t_0, $time_step);
	$t = str_pad(dechex($t), 16, '0', STR_PAD_LEFT);
	$hash_hmac_data_chr = hexdec($t);
	$hash_hmac_data = generate_hash_hmac_data($hash_hmac_data_chr);
	$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
	$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
	$otp = generate_HOTP_TOTP_value($truncated_data, $digits);

	echo '<br/><b>HOTP (RFC 4226), TOTP (RFC 6238), OCRA (RFC 6287) and OAuth 1.0a (RFC 5849), OAuth 2.0 (RFC 6749) test application</b><br/>TOTP one-time-password (Google Authenticator): <b>' . $otp . '</b><br/><br/><br/>';
	echo '<table align="justify" border="1" width="100%"><tr><td width="50%">';
	echo '<b>request:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr></table>';
 
}
elseif (($_POST['ocra_key'] != '') && ($_POST['ocra_suite'] != '') && (is_numeric($_POST['ocra_counter']) || $_POST['ocra_counter'] == null) && (isset($_POST['ocra_question'])) && ($_POST['ocra_password'] != '') && (isset($_POST['ocra_session_information'])) && (is_numeric($_POST['ocra_timestamp']) || $_POST['ocra_timestamp'] == null))
{
	$key = convert_to_character($_POST['ocra_key']);
	$ocra_suite = strtoupper($_POST['ocra_suite']);
	$counter = $_POST['ocra_counter'];
	$question = $_POST['ocra_question'];
	$password = $_POST['ocra_password'];
	$session_information = convert_to_hex($_POST['ocra_session_information']);
	$timestamp = dechex($_POST['ocra_timestamp']);

	$hash_hmac_data_ocra = array();
	$hash_hmac_data_ocra = generate_hash_hmac_data_ocra($key, $ocra_suite, $counter, $question, $password, $session_information, $timestamp);
	$hash_hmac_algo = $hash_hmac_data_ocra[0];
	$hash_hmac_data = $hash_hmac_data_ocra[1];
	$hash_hmac_key = $hash_hmac_data_ocra[2];
	$digits = $hash_hmac_data_ocra[3];
	$hash_hmac = generate_hash_hmac($hash_hmac_algo, $hash_hmac_data, $hash_hmac_key);
	$truncated_data = generate_truncated_value($hash_hmac, $hash_hmac_algo);
	$otp = generate_HOTP_TOTP_value($truncated_data, $digits);

	echo '<br/><b>HOTP (RFC 4226), TOTP (RFC 6238), OCRA (RFC 6287) and OAuth 1.0a (RFC 5849), OAuth 2.0 (RFC 6749) test application</b><br/>OCRA one-time-password: <b>' . $otp . '</b><br/><br/><br/>';
	echo '<table align="justify" border="1" width="100%"><tr><td width="50%">';
	echo '<b>request:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr></table>';

}
elseif (is_numeric($_POST['oauth_timestamp']))
{
	//request token values as temporary credentials
	$oauth_consumer_secret = $_POST['oauth_consumer_secret'];
	$oauth_token_secret = $_POST['oauth_token_secret'];

	$base_url = $_POST['base_url_01'];
	$data = $_POST['data'];
	$oauth_callback = $_POST['oauth_callback'];
	$oauth_consumer_key = $_POST['oauth_consumer_key'];
	$oauth_nonce = sha1(time() . rand(0,getrandmax()));
	$oauth_signature_method = $_POST['oauth_signature_method'];
	$oauth_timestamp = time();
	$oauth_token = $_POST['oauth_token_key'];
	$oauth_verifier = $_POST['oauth_verifier'];
	$oauth_version = $_POST['oauth_version'];

	$string_merge = '';
	$string = '';

	$string_merge = create_string_merge($data, $oauth_callback, $oauth_consumer_key, $oauth_nonce, $oauth_signature_method, $oauth_timestamp, $oauth_token, $oauth_verifier, $oauth_version);
	$string = create_string($base_url, $string_merge);

	$oauth_signature = '';
	$oauth_signature = create_oauth_signature($oauth_signature_method, $oauth_consumer_secret, $oauth_token_secret, $string, $oauth_private_key);

	$url = $base_url . '?' . $string_merge . '&' . 'oauth_signature' . '=' . $oauth_signature;
	$response = get_method_url($url, $proxy);

	$variable_pairs = array();
	$variable_pairs = parse_response($response);

	$html_oauth_url_01 = $response['url'];
	$html_oauth_base_url_01 = $base_url;
	$html_oauth_credential_01 = urldecode($response['content']);

	//get authorized token values of resource owner
	$oauth_consumer_secret = $_POST['oauth_consumer_secret'];
	$oauth_token_secret = $variable_pairs['oauth_token_secret'];

	$base_url = $_POST['base_url_02'];
	$data = $_POST['data'];
	$oauth_callback = $_POST['oauth_callback'];
	$oauth_consumer_key = $_POST['oauth_consumer_key'];
	$oauth_nonce = sha1(time() . rand(0,getrandmax()));
	$oauth_signature_method = $_POST['oauth_signature_method'];
	$oauth_timestamp = time();
	$oauth_token = $variable_pairs['oauth_token'];
	$oauth_verifier = $_POST['oauth_verifier'];
	$oauth_version = $_POST['oauth_version'];

	$string_merge = '';
	$string = '';

	$string_merge = create_string_merge($data, $oauth_callback, $oauth_consumer_key, $oauth_nonce, $oauth_signature_method, $oauth_timestamp, $oauth_token, $oauth_verifier, $oauth_version);
	$string = create_string($base_url, $string_merge);

	$oauth_signature = '';
	$oauth_signature = create_oauth_signature($oauth_signature_method, $oauth_consumer_secret, $oauth_token_secret, $string, $oauth_private_key);

	$url = $base_url . '?' . $string_merge . '&' . 'oauth_signature' . '=' . $oauth_signature;
	$response = get_method_url($url, $proxy);

	$variable_pairs = array();
	$variable_pairs = parse_response($response);

	$html_oauth_url_02 = $response['url'];
	$html_oauth_base_url_02 = $base_url;
	$html_oauth_credential_02 = urldecode($response['content']);

	//get data using authorized token values of resource owner
	$oauth_consumer_secret = $_POST['oauth_consumer_secret'];
	$oauth_token_secret = $variable_pairs['oauth_token_secret'];

	$base_url = $_POST['base_url_03'];
	$data = $_POST['data'];
	$oauth_callback = $_POST['oauth_callback'];
	$oauth_consumer_key = $_POST['oauth_consumer_key'];
	$oauth_nonce = sha1(time() . rand(0,getrandmax()));
	$oauth_signature_method = $_POST['oauth_signature_method'];
	$oauth_timestamp = time();
	$oauth_token = $variable_pairs['oauth_token'];
	$oauth_verifier = $_POST['oauth_verifier'];
	$oauth_version = $_POST['oauth_version'];

	$string_merge = '';
	$string = '';

	$string_merge = create_string_merge($data, $oauth_callback, $oauth_consumer_key, $oauth_nonce, $oauth_signature_method, $oauth_timestamp, $oauth_token, $oauth_verifier, $oauth_version);
	$string = create_string($base_url, $string_merge);

	$oauth_signature = '';
	$oauth_signature = create_oauth_signature($oauth_signature_method, $oauth_consumer_secret, $oauth_token_secret, $string, $oauth_private_key);

	$url = $base_url . '?' . $string_merge . '&' . 'oauth_signature' . '=' . $oauth_signature;
	$response = get_method_url($url, $proxy);

	$variable_pairs = array();
	$variable_pairs = parse_response($response);

	$html_oauth_url_03 = $response['url'];
	$html_oauth_base_url_03 = $base_url;
	$html_oauth_credential_03 = urldecode($response['content']);

	echo '<br/><b>HOTP (RFC 4226), TOTP (RFC 6238), OCRA (RFC 6287) and OAuth 1.0a (RFC 5849), OAuth 2.0 (RFC 6749) test application</b><br/>OAuth 1.0a responses:<br/><br/><br/>';
	echo '<table align="justify" border="1" width="100%"><tr><td width="50%">';
	echo '<b>request:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '<a href="" . $html_oauth_url_01 . "" target="_blank">" . $html_oauth_base_url_01 . "?...</a>';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo $html_oauth_credential_01;
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '<a href="" . $html_oauth_url_02 . "" target="_blank">" . $html_oauth_base_url_02 . "?...</a>';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo $html_oauth_credential_02;
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '<a href="" . $html_oauth_url_03 . "" target="_blank">" . $html_oauth_base_url_03 . "?...</a>';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo $html_oauth_credential_03;
	echo '</td></tr></table>';

}
elseif (!empty($_POST['base_url_04']))
{
	//redirect browser to hosted WEB2 application
	header('Location: ' . $_POST['base_url_04']);

}
else
{

	echo '<br/><b>HOTP (RFC 4226), TOTP (RFC 6238), OCRA (RFC 6287) and OAuth 1.0a (RFC 5849), OAuth 2.0 (RFC 6749) test application</b><br/>Please, press <b>NOW!</b> button to compute a one-time-password or get access to data using OAuth protocol!<br/><br/><br/>';
	echo '<table align="justify" border="1" width="100%"><tr><td width="50%">';
	echo '<b>request:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>request token (temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>authorized request token (authorized temporary credentials)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>request:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr><tr><td width="50%">';
	echo '<b>response:</b><br/>access token (access data)';
	echo '</td><td width="50%">';
	echo '-';
	echo '</td></tr></table>';

}

$date = new DateTime('@' . time());

$html_body = '';
$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc4226.txt" target="_blank"><b>IETF RFC 4226</b></a><b> - HOTP: An HMAC-Based One-Time Password Algorithm (December, 2005)</b><br/><br/>';
$html_body = $html_body . '<form action="index.php" method="post"><table><tr><td>current counter</td><td><input type="text" name="hotp_data" value="0" /></td></tr><tr><td>shared secret key (password)</td><td><input type="text" name="hotp_key" value="12345678901234567890" /></td></tr><tr><td>hash algorithm</td><td><select name="hotp_algo"><option value="sha1" selected="selected">SHA-1</option></select></td></tr><tr><td>length of output (digits)</td><td><input type="text" name="hotp_digits" value="6" /></td></tr><tr><td>get HOTP</td><td><input type="submit" value="NOW!" /></td></tr></table></form>';
$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc6238.txt" target="_blank"><b>IETF RFC 6238</b></a><b> - TOTP: Time-Based One-Time Password Algorithm (May, 2011)</b><br/><br/>';
$html_body = $html_body . '<form action="index.php" method="post"><table><tr><td>current Unix time</td><td><input type="text" name="totp_data" value="' . time() . '" /></td></tr><tr><td>shared secret key (password)</td><td><input type="text" name="totp_key" value="12345678901234567890" /></td></tr><tr><td>hash algorithm</td><td><select name="totp_algo"><option value="sha1" selected="selected">SHA-1</option><option value="sha256">SHA-256</option><option value="sha512">SHA-512</option></select></td></tr><tr><td>length of output (digits)</td><td><input type="text" name="totp_digits" value="8" /></td></tr><tr><td>time step (in seconds)</td><td><input type="text" name="totp_time_step" value="30" /></td></tr><tr><td>time window size (+/-)</td><td><input type="text" name="totp_step_time_window" value="1" /></td></tr><tr><td>initial time</td><td><input type="text" name="totp_time_initial" value="0" /></td></tr><tr><td>get TOTP</td><td><input type="submit" value="NOW!" /></td></tr></table></form>';
$html_body = $html_body . '<br/><b>Google Authenticator</b> compatibility (added <b>base32_decode()</b> function)<br/><br/>';
$html_body = $html_body . '<form action="index.php" method="post"><table><tr><td>current Unix time</td><td><input type="text" name="google_totp_data" value="' . time() . '" /></td></tr><tr><td>shared secret key (password)</td><td><input type="text" name="google_totp_key" value="ABCDABCDABCDABCDABCD" /></td></tr><tr><td>hash algorithm</td><td><select name="google_totp_algo"><option value="sha1" selected="selected">SHA-1</option><option value="sha256">SHA-256</option><option value="sha512">SHA-512</option></select></td></tr><tr><td>length of output (digits)</td><td><input type="text" name="google_totp_digits" value="6" /></td></tr><tr><td>time step (in seconds)</td><td><input type="text" name="google_totp_time_step" value="30" /></td></tr><tr><td>time window size (+/-)</td><td><input type="text" name="google_totp_step_time_window" value="1" /></td></tr><tr><td>initial time</td><td><input type="text" name="google_totp_time_initial" value="0" /></td></tr><tr><td>get TOTP</td><td><input type="submit" value="NOW!" /></td></tr></table></form>';
$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc6287.txt" target="_blank"><b>IETF RFC 6287</b></a><b> - OCRA: OATH Challenge-Response Algorithm (June, 2011)</b><br/><br/>';
$html_body = $html_body . '<form action="index.php" method="post"><table><tr><td>K (Key)</td><td><input type="text" name="ocra_key" value="31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334" /></td></tr><tr><td>OCRASuite</td><td><input type="text" name="ocra_suite" value="OCRA-1:HOTP-SHA512-10:QA10-PSHA512-T1M" /></td></tr><tr><td>C (Counter)</td><td><input type="text" name="ocra_counter" value="" /></td></tr><tr><td>Q (Question)</td><td><input type="text" name="ocra_question" value="SIG1000000" /></td></tr><tr><td>P (Password)</td><td><input type="text" name="ocra_password" value="dead00beef" /></td></tr><tr><td>S (Session Information)</td><td><input type="text" name="ocra_session_information" value="" /></td></tr><tr><td>T (Timestamp)</td><td><input type="text" name="ocra_timestamp" value="20107446" /></td></tr><tr><td>get OCRA</td><td><input type="submit" value="NOW!" /></td></tr></table></form>';
$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc5849.txt" target="_blank"><b>IETF RFC 5849</b></a><b> - The OAuth 1.0 Protocol (April, 2010)</b><br/><br/>';
$html_body = $html_body . '<form action="index.php" method="post"><table>
<tr><td>endpoint URI (request token service base URL)</td><td><input type="text" name="base_url_01" value="http://term.ie/oauth/example/request_token.php" readonly /></td></tr>
<tr><td>endpoint URI (authorize token service base URL)</td><td><input type="text" name="base_url_02" value="http://term.ie/oauth/example/access_token.php" readonly /></td></tr>
<tr><td>endpoint URI (access data service base URL)</td><td><input type="text" name="base_url_03" value="http://term.ie/oauth/example/echo_api.php" readonly /></td></tr>
<tr><td>data (anything)</td><td><input type="text" name="data" value="OAuth 1.0a credentials requested by Aron (using HOTP or TOTP value)" /></td></tr>
<tr><td>oauth consumer key (client username)</td><td><input type="text" name="oauth_consumer_key" value="key" readonly /></td></tr>
<tr><td>oauth consumer secret (client password)</td><td><input type="text" name="oauth_consumer_secret" value="secret" readonly /></td></tr>
<tr><td>oauth token key (temporary username)</td><td><input type="text" name="oauth_token_key" value="" readonly /></td></tr>
<tr><td>oauth token secret (temproray password)</td><td><input type="text" name="oauth_token_secret" value="" readonly /></td></tr>
<tr><td>oauth signature method</td><td><select name="oauth_signature_method"><option value="HMAC-SHA1" selected="selected">HMAC-SHA1</option><option value="PLAINTEXT">PLAINTEXT</option><option value="RSA-SHA1">RSA-SHA1</option></select></td></tr>
<tr><td>oauth nonce (unique random)</td><td><input type="text" name="oauth_nonce" value="' . sha1(time() . rand(0,getrandmax())) . '" readonly /></td></tr>
<tr><td>oauth timestamp (Unix time)</td><td><input type="text" name="oauth_timestamp" value="' . time() . '" readonly /></td></tr>
<tr><td>oauth callback (redirect URL)</td><td><input type="text" name="oauth_callback" value="" readonly /></td></tr>
<tr><td>oauth verifier (server generated)</td><td><input type="text" name="oauth_verifier" value="" readonly /></td></tr>
<tr><td>oauth version</td><td><input type="text" name="oauth_version" value="1.0" readonly /></td></tr>
<tr><td>get Access to Data using OAuth 1.0a</td><td><input type="submit" value="NOW!" /></td></tr></table></form>';
$html_body = $html_body . '<br/><a href="http://www.ietf.org/rfc/rfc6749.txt" target="_blank"><b>IETF RFC 6749</b></a><b> - The OAuth 2.0 Authorization Framework (October, 2012)</b><br/><br/>';
$html_body = $html_body . '<form action="index.php" method="post"><table>
<tr><td>endpoint URI (client application)</td><td><input type="text" name="base_url_04" value="Please, set your Facebook application \"Canvas URL\" or \"Secure Canvas URL\" here!" /></td></tr>
<tr><td>get Access to Data using OAuth 2.0</td><td><input type="submit" value="NOW!" /></td></tr></table></form>';
$html_body = $html_body . '/**<br/>&nbsp;*&nbsp;NOTE:<br/>&nbsp;*&nbsp;Please, follow the installation steps below!<br/>&nbsp;*&nbsp;1) upload attached <b>index_oauth2_facebook.php</b> to a web server,<br/>&nbsp;*&nbsp;2) configure it as a new application on <b>Facebook</b> developer portal,<br/>&nbsp;*&nbsp;3) set its public URL at <b>endpoint URI (client application)</b>!<br/>&nbsp;*/<br/>';
$html_body = $html_body . '<br/><br/><br/>/**<br/>&nbsp;*&nbsp;The tables below show the results of HOTP and TOTP generation self-test function.<br/>&nbsp;*&nbsp;Please, compare these computed values with the given input-output data written in the related RFCs!<br/>&nbsp;*&nbsp;The self-test was performed at: <b>' . $date->format('Y-m-d H:i:s') . '</b><br/>&nbsp;*/<br/>';
$html_body = $html_body . perform_self_test();
$html = '<html><head><title>HOTP (RFC 4226), TOTP (RFC 6238), OCRA (RFC 6287) and OAuth 1.0a (RFC 5849), OAuth 2.0 (RFC 6749) test application</title></head><body>' . $html_body . '</body></html>';



?>



<?php echo $html; ?>


