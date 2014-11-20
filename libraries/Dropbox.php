<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

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

class Dropbox
{
    const SCHEME        = 'https';
    const HOST          = 'api.dropbox.com';
    const AUTHORIZE_URI = '/oauth/authorize';
    const REQUEST_URI   = '/oauth/request_token';
    const ACCESS_URI    = '/oauth/access_token';
    
    const DEFAULT_ROOT  = 'dropbox';//Customize which root you wish the library to default to
    const API_VERSION   = '1';
    
    const HTTP_1        = '1.1';
    const LINE_END      = "\r\n";
    
    const DEBUG = false;
    
    //Array that should contain the consumer secret and
    //key which should be passed into the constructor.
    private $_consumer = false;
    private $_access = false;
    
    private $_header = array(
        'Host'=>self::HOST,
        'Connection'=>'close',
        'User-Agent'=>'CodeIgniter',
        'Accept-encoding'=>'identity'
    );
    
    /**
     * Pass in a parameters array which should look as follows:
     * array('key'=>'example.com', 'secret'=>'mysecret');
     *
     * @param array $params
     */
    public function __construct($params)
    {
        $this->CI =& get_instance();
        $this->CI->load->helper('oauth');
        $this->CI->load->helper('string');
        
        if(!array_key_exists('method', $params))$params['method'] = 'GET';
        $params['algorithm'] = OAUTH_ALGORITHMS::HMAC_SHA1; //Only thing available in dropbox
        
        $this->_consumer = array_diff_key($params, array('access'=>0));
        if(array_key_exists('access', $params))$this->_access = $params['access'];
    }
    
    /**
     * Sets OAuth access data to authenticate a user with dropbox.
     *
     * @param array $access an array of the form
     *                      array('oauth_token'=>url encoded token,'oauth_token_secret'=>url encoded secret)
     **/
    public function set_oauth_access(array $access)
    {
        $this->_access = $access;
    }
    
    /**
     * This is called to begin the oauth token exchange. This should only
     * need to be called once for a user, provided they allow oauth access.
     * It will return a URL that your site should redirect to, allowing the
     * user to login and accept your application.
     *
     * @param string $callback the page on your site you wish to return to
     *                         after the user grants your application access.
     * @return mixed either the URL to redirect to, or if they specified HMAC
     *         signing an array with the token_secret and the redirect url
     */
    public function get_request_token($callback)
    {
        $baseurl = self::SCHEME.'://'.self::HOST.'/'.self::API_VERSION.self::REQUEST_URI;

        //Generate an array with the initial oauth values we need
        $auth = build_auth_array($baseurl, $this->_consumer['key'], $this->_consumer['secret'],
                                 //array('oauth_callback'=>urlencode($callback)),
                                 array(),
                                 $this->_consumer['method'], $this->_consumer['algorithm']);
        //Create the "Authorization" portion of the header
        $str = "";
        foreach($auth as $key => $value)
            $str .= ",{$key}=\"{$value}\"";
        $str = 'Authorization: OAuth '.substr($str, 1);
        //Send it
        $response = $this->_connect($baseurl, $str, $this->_consumer['method']);
        
        //We should get back a request token and secret which
        //we will add to the redirect url.
        parse_str($response, $resarray);
        
        $callback = urlencode($callback);
        
        //Return the full redirect url and let the user decide what to do from there.
        $redirect = self::SCHEME.'://www.dropbox.com/'.self::API_VERSION.self::AUTHORIZE_URI."?oauth_token={$resarray['oauth_token']}&oauth_callback={$callback}";
        
        return array('token_secret'=>$resarray['oauth_token_secret'], 'redirect'=>$redirect);
    }
    
    /**
     * This is called to finish the oauth token exchange. This too should
     * only need to be called once for a user. The token returned should
     * be stored in your database for that particular user.
     *
     * @param string $token this is the oauth_token returned with your callback url
     * @param string $secret this is the token secret supplied from the request (Only required if using HMAC)
     * @param string $verifier this is the oauth_verifier returned with your callback url
     * @return array access token and token secret
     */
    public function get_access_token($secret, $token = false)
    {
        //If no request token was specified then attempt to get one from the url
        if($token === false && isset($_GET['oauth_token']))$token = $_GET['oauth_token'];
        //If all else fails attempt to get it from the request uri.
        if($token === false)
        {
            $uri = $_SERVER['REQUEST_URI'];
            $uriparts = explode('?', $uri);

            $authfields = array();
            parse_str($uriparts[1], $authfields);
            $token = $authfields['oauth_token'];
        }
        
        $tokenddata = array('oauth_token'=>urlencode($token));
        if($secret !== false)$tokenddata['oauth_token_secret'] = urlencode($secret);
        
        $baseurl = self::SCHEME.'://'.self::HOST.'/'.self::API_VERSION.self::ACCESS_URI;
        //Include the token and verifier into the header request.
        $auth = get_auth_header($baseurl, $this->_consumer['key'], $this->_consumer['secret'],
                                $tokenddata, $this->_consumer['method'], $this->_consumer['algorithm']);
        $response = $this->_connect($baseurl, $auth, $this->_consumer['method']);
        //Parse the response into an array it should contain
        //both the access token and the secret key. (You only
        //need the secret key if you use HMAC-SHA1 signatures.)
        parse_str($response, $oauth);
        
        $this->_access = $oauth;
        
        //Return the token and secret for storage
        return $oauth;
    }
    
    /**
     * Retrieve information about the authenticated users account.
     *
     * @return object response
     **/
    public function account()
    {
        return $this->_response_request('/account/info');
    }
    
    /**
     * Retrieve a file from the currently authenticated user's dropbox 
     * account. Note: The path should be relative to the root dropbox
     * folder and the destination should be relative to your sites root
     * folder.
     *
     * @param mixed $destination The path to create the new file at or false if you want the file contents returned.
     * @param string $path The path to the file or folder in question.
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return mixed true on success false on failure if a destination is specified otherwise the contents of the file are returned as a string
     **/
    public function get($destination, $path, $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        return $this->_content_request("/files/{$root}/{$path}", $destination);
    }
    
    /**
     * Retrieve thumbnail data from image files at specified path.
     *
     * @param string $destination The path to create the thumbnail image.
     * @param string $path The path to the image file or folder.
     * @param array $params (optional) Consult the Dropbox API documentation for more details
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return boolean true on success false on failure.
     **/
    public function thumbnails($destination, $path, array $params = array('size'=>'small', 'format'=>'JPEG'), $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        $parstr = http_build_query($params);
        return $this->_content_request("/thumbnails/{$root}/{$path}?{$parstr}", $destination);
    }
    
    /**
     * Adds a local file to the authenticated user's dropbox account using the post method
     *
     * @param string $dbpath The location in the user's dropbox to place the file.
     * @param string $filepath The relative path on the server of the file to upload.
     * @param array $params (optional) Consult the Dropbox API documentation for more details
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function add($dbpath, $filepath, array $params = array(), $root=self::DEFAULT_ROOT)
    {
        $dbpath = str_replace(' ', '%20', $dbpath);
        $filename = rawurlencode($filepath);
        $parstr = empty($params) ? '' : '&'.http_build_query($params);
        $uri = reduce_double_slashes("/files/{$root}/{$dbpath}?file={$filename}{$parstr}");
        $specialhost = 'api-content.dropbox.com';
        return $this->_post_request($uri, array('file'=>'@'.$filepath), $specialhost);
    }
    
    /**
     * Retrieve metadata information about files or folders in the currently
     * authenticated user's dropbox account. Note: The path should be relative
     * to the root dropbox folder.
     *
     * @param string $path The path to the file or folder in question.
     * @param array $params (optional) Consult the Dropbox API documentation for more details
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function metadata($path, array $params = array(), $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        $parstr = empty($params) ? '' : '?'.http_build_query($params);
        return $this->_response_request("/metadata/{$root}/{$path}{$parstr}");
    }
    
    /**
     * Retrieve revision data about files or folders in the currently
     * authenticated user's dropbox account. Note: The path should be relative
     * to the root drop box folder.
     *
     * @param string $path The path to the file or folder in question
     * @param array $params (optional) Consult the Dropbox API documentation for more details
     * @param string $root (optional) Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function revisions($path, array $params = array(), $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        $parstr = empty($params) ? '' : '?'.http_build_query($params);
        return $this->_response_request("/revisions/{$root}/{$path}{$parstr}");
    }
    
    /**
     * Restore a file or folder to a previous revision.
     *
     * @param string $path The path to the file or folder in question
     * @param string $revision The rev hash to revert to.
     * @param string $root (optional) Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function restore($path, $revision, $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        return $this->_post_request("/restore/{$root}/{$path}?rev={$revision}");
    }
    
    /**
     * Retrieve metadata for all files and folders that match the search query
     *
     * @param string $path The path to the file or folder in question
     * @param string $query The search query must be at least 3 characters in length
     * @param array $params (optional) Consult the Dropbox API documentation for more details
     * @param string $root (optional) Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function search($path, $query, array $params = array(), $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        $query = rawurlencode($query);
        $parstr = empty($params) ? '' : '&'.http_build_query($params);
        return $this->_response_request("/search/{$root}/{$path}?query={$query}{$parstr}");
    }
    
    /**
     * Retrieve a shareable link to files or folders. The link can be used
     * publicly and directs to a preview page of the file. Also returns the
     * link's expiration date.
     *
     * @param string $path The path to the file or folder in question
     * @param array $params (optional) Consult the Dropbox API documentation for more details
     * @param string $root (optional) Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function shares($path, array $params = array(), $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        $parstr = empty($params) ? '' : '?'.http_build_query($params);
        return $this->_response_request("/shares/{$root}/{$path}{$parstr}");
    }
    
    /**
     * Retrieve a link directly to a file.
     *
     * @param string $path The path to the file or folder in question
     * @param string $root (optional) Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function media($path, $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        return $this->_response_request("/media/{$root}/{$path}");
    }
    
    /**
     * Copies a file or folder in dropbox to another location within dropbox.
     *
     * @param string $from The relative path to the file to be copied.
     * @param string $to The relative path (Including file or folder name) to place to copy.
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function copy($from, $to, $root=self::DEFAULT_ROOT)
    {
        return $this->_response_request('/fileops/copy?from_path='.rawurlencode($from).'&to_path='.rawurlencode($to).'&root='.$root);
    }

    /**
     * Creates a reference string that can be used to copy a file to another
     * user's Dropbox.
     *
     * @param string $path The path to the file or folder in question
     * @param string $root (optional) Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function copy_ref($path, $root=self::DEFAULT_ROOT)
    {
        $path = str_replace('%2F', '/', rawurlencode($path));
        return $this->_response_request("/copy_ref/{$root}/{$path}");
    }

    /**
     * Create a folder relative to the user's Dropbox root or the user's
     * application sandbox folder.
     *
     * @param string $path The path to the new folder to create.
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function create_folder($path, $root=self::DEFAULT_ROOT)
    {
        return $this->_response_request('/fileops/create_folder?path='.rawurlencode($path).'&root='.$root);
    }
    
    /**
     * Delete a folder or file relative to the user's Dropbox root or
     * the user's application sandbox folder.
     *
     * @param string $path The path to the folder or file to delete.
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function delete($path, $root=self::DEFAULT_ROOT)
    {
        return $this->_response_request('/fileops/delete?path='.rawurlencode($path).'&root='.$root);
    }

    /**
     * Periodically call to get a list of "delta entries", which are instructions
     * on how to update your local state to match the server's state.
     *
     * @param string $cursor (optional) The cursor from the last delta call.
     * @return object response
     **/
    public function delta($cursor=false)
    {
        $data = array();
        if($cursor !== false)
        {
            //Add the cursor to the access array to generate
            //the correct signature base string
            $this->_access['cursor'] = $cursor;
            $data['cursor'] = $cursor;
        }
        $obj = $this->_post_request('/delta', $data);
        //Reset our access array to prepare for the next round of calls.
        if(array_key_exists('cursor', $this->_access))unset($this->_access['cursor']);
        return $obj;
    }

    /**
     * Copies a file or folder in dropbox to another location within dropbox.
     *
     * @param string $from The relative path to the file to be moved.
     * @param string $to The relative path (Including file or folder name) to the new location.
     * @param string $root Either 'dropbox' or 'sandbox'
     * @return object response
     **/
    public function move($from, $to, $root=self::DEFAULT_ROOT)
    {
        return $this->_response_request('/fileops/move?from_path='.rawurlencode($from).'&to_path='.rawurlencode($to).'&root='.$root);
    }
    
    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Below are the private methods used to create and send the requests to the dropbox api server.
    ////////////////////////////////////////////////////////////////////////////////////////////////
    
    private function _post_request($uri, $data = false, $specialhost = false)
    {
        $request = "POST {$uri} HTTP/".self::HTTP_1.self::LINE_END;
        $host = self::HOST;
        $extra = array();
        if($specialhost !== false)
        {
            $host = $specialhost;
            $extra['Host'] = $specialhost;
        }
        $url = self::SCHEME."://{$host}/".self::API_VERSION.$uri;
        
        $header = $this->_build_header($url, 'POST', $request, self::LINE_END, $extra);
        if(self::DEBUG)error_log($header);
        
        $response = $this->_connect($url, $header, 'POST', $data);
        return json_decode($response);
    }
    
    private function _content_request($uri, $destination)
    {
        $uri = reduce_double_slashes('/'.self::API_VERSION.$uri);
        $request = "GET {$uri} HTTP/".self::HTTP_1.self::LINE_END;
        $specialhost = 'api-content.dropbox.com';
        $url = self::SCHEME.'://'.$specialhost.$uri;
        
        $header = $this->_build_header($url, 'GET', $request, self::LINE_END, array('Host'=>$specialhost));
        if(self::DEBUG)error_log($header);
        
        return $this->_connect($url, $header, 'GET', false, $destination);
    }
    
    private function _response_request($uri)
    {
        $uri = reduce_double_slashes('/'.self::API_VERSION.$uri);
        $request = "GET {$uri} HTTP/".self::HTTP_1.self::LINE_END;
        $url = self::SCHEME.'://'.self::HOST.$uri;
        
        $header = $this->_build_header($url, 'GET', $request, self::LINE_END);
        if(self::DEBUG)error_log($header);
        
        $response = $this->_connect($url, $header, 'GET');
        return json_decode($response);
    }
    
    private function _build_header($url, $method, $prepend, $append, $overwrite = array())
    {
        $str = $prepend === false ? '' : $prepend;
        foreach($this->_header AS $key=>$value)
        {
            if(array_key_exists($key, $overwrite))$str .= $key.': '.$overwrite[$key].self::LINE_END;
            else $str .= $key.': '.$value.self::LINE_END;
        }
        if($this->_access !== false && $url !== false)$str .= get_auth_header($url, $this->_consumer['key'], $this->_consumer['secret'], $this->_access, $method, $this->_consumer['algorithm']);
        $str .= $append === false ? '' : $append;

        return $str;
    }
    
    private function _connect($url, $header, $request, $postdata = false, $destination = false)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC ) ;
        curl_setopt($ch, CURLOPT_SSLVERSION, 1); // Require TLS
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_CAINFO, __DIR__."/certs/trusted-certs.crt");
        curl_setopt($ch, CURLOPT_CAPATH, __DIR__."/certs/");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $request);
        curl_setopt($ch, CURLOPT_HTTPHEADER, explode(self::LINE_END, $header));
        curl_setopt($ch, CURLINFO_HEADER_OUT, true);

        if(is_array($postdata))
        {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
        }
        
        $response = curl_exec($ch);
        
        if(self::DEBUG)
        {
            error_log(print_r(curl_getinfo($ch), true));
            error_log($response);
        }
        
    	$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    	curl_close($ch);
        
        //If this is a content request write the file
        if($destination !== false)
        {
        	//If the response was good then write
            //the file and return true
        	if($code == '200')
        	{
				$fh = fopen($destination, 'w');
				fwrite($fh, $response);
				if($fh !== false)
                {
                    fclose($fh);
                    return true;
                }
			}
            //The response was bad or the file couldn't
            //be written so return false.
			return false;
        }
        else return $response;
    }
}
// ./application/libraries
