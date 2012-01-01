<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Example extends CI_Controller
{
    public function __construct()
    {
    	parent::__construct();
        $this->load->library('session');
        $this->load->helper('url');
    }
    // Call this method first by visiting http://SITE_URL/example/request_dropbox
    public function request_dropbox()
	{
		$params['key'] = 'YOUR DROPBOX CONSUMER KEY';
		$params['secret'] = 'YOUR DROPBOX CONSUMER SECRET';
		
		$this->load->library('dropbox', $params);
		$data = $this->dropbox->get_request_token(site_url("example/access_dropbox"));
		$this->session->set_userdata('token_secret', $data['token_secret']);
		redirect($data['redirect']);
	}
	//This method should not be called directly, it will be called after 
    //the user approves your application and dropbox redirects to it
	public function access_dropbox()
	{
		$params['key'] = 'YOUR DROPBOX CONSUMER KEY';
		$params['secret'] = 'YOUR DROPBOX CONSUMER SECRET';
		
		$this->load->library('dropbox', $params);
		
		$oauth = $this->dropbox->get_access_token($this->session->userdata('token_secret'));
		
		$this->session->set_userdata('oauth_token', $oauth['oauth_token']);
		$this->session->set_userdata('oauth_token_secret', $oauth['oauth_token_secret']);
        redirect('example/test_dropbox');
	}
	//Once your application is approved you can proceed to load the library
    //with the access token data stored in the session. If you see your account
    //information printed out then you have successfully authenticated with
    //dropbox and can use the library to interact with your account.
	public function test_dropbox()
	{
		$params['key'] = 'YOUR DROPBOX CONSUMER KEY';
		$params['secret'] = 'YOUR DROPBOX CONSUMER SECRET';
		$params['access'] = array('oauth_token'=>urlencode($this->session->userdata('oauth_token')),
								  'oauth_token_secret'=>urlencode($this->session->userdata('oauth_token_secret')));
		
		$this->load->library('dropbox', $params);
		
        $dbobj = $this->dropbox->account();
		
        print_r($dbobj);
	}
}

/* End of file example.php */
/* Location: ./application/controllers/welcome.php */