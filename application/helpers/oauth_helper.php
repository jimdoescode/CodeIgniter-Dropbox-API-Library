<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/*
Copyright (C) 2011 by Jim Saunders

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/**
 * Defines the different OAuth Signing algorithms. You 
 * should use this instead of writing them out each time.
 */
class OAUTH_ALGORITHMS
{
    const HMAC_SHA1 = 'HMAC-SHA1';
    const RSA_SHA1 = 'RSA-SHA1';
}

/**
 * Signs an array of oauth parameters according to the 1.0 spec using
 * the hmac-sha1 hasing algorithm
 *
 * @param string $method either GET or POST
 * @param string $baseurl the baseurl we are authenticating againts
 * @param string $secret the consumer secret key
 * @param array $parameters all parameters that need to be signed (NOTE: the token secret key should be added here)
 * @return string the signature
 */
function sign_hmac_sha1($method, $baseurl, $secret, array $parameters)
{
    $data = $method.'&';
    $data .= urlencode($baseurl).'&';
    $oauth = '';
    ksort($parameters);
    //Put the token secret in if it does not exist. It
    //will be empty if it does not exist as per the spec.
    if(!array_key_exists('oauth_token_secret', $parameters))$parameters['oauth_token_secret'] = '';
    foreach($parameters as $key => $value)
    {
        //Don't include the token secret into the base string
        if(strtolower($key) != 'oauth_token_secret')$oauth .= "&{$key}={$value}";
    }
    $data .= urlencode(substr($oauth, 1));
    $secret .= '&'.$parameters['oauth_token_secret'];
    
    return base64_encode(hash_hmac('sha1', $data, $secret, true));
}

/**
 * Signs an array of oauth parameters according to the 1.0 spec using
 * the rsa-sha1 hasing algorithm
 *
 * @param string $method either GET or POST
 * @param string $baseurl the baseurl we are authenticating againts
 * @param string $certfile the location of your private certificate file
 * @param array $parameters all parameters that need to be signed
 * @return string the signature
 */
function sign_rsa_sha1($method, $baseurl, $certfile, array $parameters)
{
    $fp = fopen($certfile, "r");
    $private = fread($fp, 8192);
    fclose($fp);

    $data = $method.'&';
    $data .= urlencode($baseurl).'&';
    $oauth = '';
    ksort($parameters);

    foreach($parameters as $key => $value)
        $oauth .= "&{$key}={$value}";
    $data .= urlencode(substr($oauth, 1));

    $keyid = openssl_get_privatekey($private);
    openssl_sign($data, $signature, $keyid);
    openssl_free_key($keyid);

    return base64_encode($signature);
}

/**
 * Assembles the auth params array into a string that can
 * be put into an http header request.
 *
 * @param array $authparams the oauth parameters
 * @return string the header authorization portion with trailing \r\n
 */
function build_auth_string(array $authparams)
{
    $header = "Authorization: OAuth ";
    $auth = '';
    foreach($authparams AS $key=>$value)
    {
        //Don't include token secret
        if($key != 'oauth_token_secret')$auth .= ", {$key}=\"{$value}\"";
    }
    return $header.substr($auth, 2)."\r\n";
}

/**
 * Assemble an associative array with oauth values
 *
 * @param string $baseurl the base url we are authenticating against.
 * @param string $key your consumer key
 * @param string $secret either your consumer secret key or the file location of your rsa private key.
 * @param array $extra additional oauth parameters that should be included (you must urlencode, if appropriate, before calling this function)
 * @param string $method either GET or POST
 * @param string $algo either HMAC-SHA1 or RSA-SHA1 (NOTE: this affects what you put in for the secret parameter)
 * @return array of all the oauth parameters
 */
function build_auth_array($baseurl, $key, $secret, $extra = array(), $method = 'GET', $algo = OAUTH_ALGORITHMS::RSA_SHA1)
{
    $auth['oauth_consumer_key'] = $key;
    $auth['oauth_signature_method'] = $algo;
    $auth['oauth_timestamp'] = time();
    $auth['oauth_nonce'] = md5(uniqid(rand(), true));
    $auth['oauth_version'] = '1.0';

    $auth = array_merge($auth, $extra);
    
    //We want to remove any query parameters from the base url
    $urlsegs = explode("?", $baseurl);
    $baseurl = $urlsegs[0];
    
    //If there are any query parameters we need to make sure they
    //get signed with the rest of the auth data.
    $signing = $auth;
    if(count($urlsegs) > 1)
    {
        preg_match_all("/([\w\-]+)\=([\w\d\-\%\.\$\+\*]+)\&?/", $urlsegs[1], $matches);
        $signing = $signing + array_combine($matches[1], $matches[2]);
    }
    
    if(strtoupper($algo) == OAUTH_ALGORITHMS::HMAC_SHA1)$auth['oauth_signature'] = sign_hmac_sha1($method, $baseurl, $secret, $signing);
    else if(strtoupper($algo) == OAUTH_ALGORITHMS::RSA_SHA1)$auth['oauth_signature'] = sign_rsa_sha1 ($method, $baseurl, $secret, $signing);
  
    $auth['oauth_signature'] = urlencode($auth['oauth_signature']);
    return $auth;
}

/**
 * Creates the authorization portion of a header NOTE: This does not
 * create a complete http header. Also NOTE: the oauth_token parameter
 * should be passed in using the $extra array.
 *
 * @param string $baseurl the base url we are authenticating against.
 * @param string $key your consumer key
 * @param string $secret either your consumer secret key or the file location of your rsa private key.
 * @param array $extra additional oauth parameters that should be included (you must urlencode a parameter, if appropriate, before calling this function)
 * @param string $method either GET or POST
 * @param string $algo either HMAC-SHA1 or RSA-SHA1 (NOTE: this affects what you put in for the secret parameter)
 * @return string the header authorization portion with trailing \r\n
 */
function get_auth_header($baseurl, $key, $secret, $extra = array(), $method = 'GET', $algo = OAUTH_ALGORITHMS::RSA_SHA1)
{
    $auth = build_auth_array($baseurl, $key, $secret, $extra, $method, $algo);
    return build_auth_string($auth);
}

/* ./application/helpers/oauth_helper.php */
?>
