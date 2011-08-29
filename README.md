CodeIgniter Dropbox API Library
===============================

This library will let a user authenticate with dropbox and perform actions such as uploading files, moving files, and deleting files from their dropbox account.

Basic documentation can be found on my blog at http://jimdoescode.blogspot.com

The example controller provided will also give you a good idea of how to authenticate and use the library. 

Usage
------
Copy the files under your application directory. Then load the library like this:

$params['key'] = 'YOUR DROPBOX CONSUMER KEY';

$params['secret'] = 'YOUR DROPBOX CONSUMER SECRET';

$this->load->library('dropbox', $params);

$dbobj = $this->dropbox->account();
		
License
-------
This library is licensed under the MIT license. 

Sparks
------
You can also use this library with Sparks. Simply install using sparks then call.

$this->load->spark('dropbox/1.0.0');

Then load the library as specified in the usage.

