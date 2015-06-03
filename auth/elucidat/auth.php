<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authentication plugin for moodle
 * This plugin is designed to demonstrate how to interact with the elucidat API.
 * It is not officially supported and is for the purpose of guidance only.
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');

/**
 * Plugin for SSO authentication with elucidat.
 */
class auth_plugin_elucidat extends auth_plugin_base {

    /**
     * Constructor.
     */
    function auth_plugin_none() {
        $this->authtype = 'elucidat';
        $this->config = get_config('auth/elucidat');
    }

    function user_authenticated_hook($user, $username, $password)
    {
        global $DB, $SESSION, $CFG;

        //TODO store this stuff in the config
        $api_url = "http://api.elucidat.dev";
        $author_url = "http://author.elucidat.dev";
        $my_redirect = "http://lms.elucidat.dev";

        //TODO remove all keys before commit
        $consumer_key = “xxxx-xxxx-xxxx-xxxx-xxxxxxxx”;
        $consumer_secret = "xxxx-xxxx-xxxx-xxxx-xxxxxxxx";
        $email = $user->email;

        /*
         * This part would check if I am meant to be an Author,
         * in this example we will use user roles to differentiate, and in this case well be using the user role 'coursecreator'
         * We assume that at this point, that authors will have already have an account at elucidat.
         */
        //$course_creator_role = $DB->get_record('role', array('archetype'=>'coursecreator'));
        //if($DB->count_records('role_assignments', array('roleid' => $course_creator_role->id, 'userid' => $user->id)) > 0 ) {

            /*
             * Lets set this user as an author
             * this should really be done via the events API (role_assigned, role_unassigned), but for the purpose of example...
             */

            $this->single_sign_on($api_url, $consumer_key, $consumer_secret, $email, $author_url, $my_redirect);
        //} else {
            /*
            * Lets delete this author from elucidat
            * this should really be done via the events API (role_assigned, role_unassigned), but for the purpose of example...
            */
            //TODO

        //}

    }

    /**
     * This method demonstrates the workflow for getting an access_token for a user from elucidat, and then signing them on.
     * Take note that the access_tokens may be kept to be used in other user specific API calls, or to re-login the user
     * at a later date
     * @param $api_url
     * @param $consumer_key
     * @param $consumer_secret
     * @param $email
     * @param $author_url
     * @param $my_redirect
     */
    public function single_sign_on($api_url, $consumer_key, $consumer_secret, $email, $author_url, $my_redirect){
        //First get a nonce from the API to make our connection more secure
        $nonce = $this->get_nonce($api_url, $consumer_key, $consumer_secret);

        //If we didnt get a nonce, something went wrong otherwise continue
        if ($nonce) {
            //Make the request to elucidat for an access token
            $auth_headers = array('oauth_consumer_key' => $consumer_key,
                'oauth_nonce' => $nonce,
                'oauth_signature_method' => 'HMAC-SHA1',
                'oauth_timestamp' => time(),
                'oauth_version' => '1.0');

            $fields = array(
                'email' => urlencode($email)
            );
            $json = $this->call_elucidat($auth_headers, $fields, $api_url . '/single_sign_on', $consumer_secret);

            //Providing that an access token is received, lets log the user in
            if (isset($json['access_token'])) {
                /*
                 * at this point we have an access token we can trade in at any point for a login at elucidat,
                 * we just need to direct them to the single sign on login on the authors server to exchange the key.
                 * That doesn't have to happen now, the key will last until another key is requested for the same user.
                 * For the purpose of example we will do it now.
                 */
                //Again we need to get a nonce from the API to make our connection more secure
                $nonce = $this->get_nonce($api_url, $consumer_key, $consumer_secret);

                //If we didnt get a nonce, something went wrong otherwise continue
                if ($nonce) {
                    $url = $author_url . '/Single_sign_on_redirect/login';
                    $params = array('oauth_consumer_key' => $consumer_key,
                        'oauth_nonce' => $nonce,
                        'oauth_signature_method' => 'HMAC-SHA1',
                        'oauth_timestamp' => time(),
                        'oauth_version' => '1.0',
                        'access_token' => $json['access_token'],
                        'redirect_url' => $my_redirect);
                    $params['oauth_signature'] = $this->build_signature($consumer_secret, $params, 'GET', $url);
                    $request = $this->build_base_string($params);

                    header('Location: ' . $url . '?' . $request);
                }
            } else {
                // Something went wrong and the user was not issued with an access token.
                // Either the request was incorrect or elucidat was not able to identify the user form the given email
            }
        }
    }

    /**
     * Each request to the elucidat API must be accompanied by a unique key known as a nonce.
     * This key adds an additional level of security to the API.
     * A new key must be requested for each API call.
     * @param $api_url
     * @param $consumer_key
     * @param $consumer_secret
     * @return bool
     */
    public function get_nonce($api_url, $consumer_key, $consumer_secret){
        //First get a nonce from the API to make our connection more secure
        $auth_headers = array('oauth_consumer_key' => $consumer_key,
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_version' => '1.0');

        //Make a request to elucidat for a nonce
        $json = $this->call_elucidat($auth_headers, array(), $api_url . '/single_sign_on', $consumer_secret);

        if(isset($json['nonce'])){
            return $json['nonce'];
        }
        return false;
    }

    /**
     * Makes an API request to elucidat
     * @param $headers
     * @param $fields
     * @param $url
     * @param $consumer_secret
     * @return mixed
     */
    public function call_elucidat($headers, $fields, $url, $consumer_secret){
        //Build a signature
        $headers['oauth_signature'] = $this->build_signature($consumer_secret, $headers, 'POST', $url);

        //Build OAuth headers
        $auth_headers = 'Authorization:';
        $values = array();
        foreach($headers as $key=>$value)
            $values[] = "$key=\"" . rawurlencode($value) . "\"";
        $auth_headers .= implode(', ', $values);

        //Build the request string
        $fields_string = $this->build_base_string($fields);

        //Set the headers and post data
        $header = array($auth_headers, 'Expect:');
        $options = array(
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_HEADER => false,
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_POST => count($fields),
            CURLOPT_POSTFIELDS => $fields_string);

        //Init the request and set its params
        $request = curl_init();
        curl_setopt_array($request, $options);
        //Make the request
        $response = curl_exec($request);
        curl_close($request);

        //print_r($response);

        return json_decode($response, true);
    }

    /**
     * returns a signature for an oauth request.
     * @param $secret
     * @param $fields
     * @param $request_type
     * @param $url
     * @return string
     */
    function build_signature($secret, $fields, $request_type, $url){
        ksort($fields);
        //Build base string to be used as a signature
        $base_info = $request_type.'&'.$url.'&'.rawurlencode($this-> build_base_string($fields)); //return complete base string
        //Create the signature from the secret and base string
        $composite_key = rawurlencode($secret);
        return base64_encode(hash_hmac('sha1', $base_info, $composite_key, true));

    }

    /**
     * Builds a uri segment from an array of fields
     * @param $fields
     * @return string
     */

    function build_base_string($fields){
        $r = array();
        foreach($fields as $key=>$value){
            $r[] = "$key=" . rawurlencode($value);
        }
        return implode('&', $r); //return complete base string

    }

    function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return false;
    }

    /**
     * Returns true if plugin can be manually set.
     *
     * @return bool
     */
    function can_be_manually_set() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.html";
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        return true;
    }

}


