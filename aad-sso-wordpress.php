<?php

/*
Plugin Name: Azure Active Directory First-Party Single Sign-on for WordPress
Plugin URI: http://webdevstudios.com
Description: Allows you to use your organization's Azure Active Directory user accounts to log in to WordPress. If your organization is using Office 365, your user accounts are already in Azure Active Directory. This plugin uses OAuth 2.0 to authenticate users, and the Azure Active Directory Graph to get group membership and other details.
Author: WebDevStudios
Version: 0.2c
Author URI: http://webdevstudios.com/
*/

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

define( 'AADSSO_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'AADSSO_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

define( 'AADSSO_SETTINGS_PATH', AADSSO_PLUGIN_DIR . 'Settings.json' );

require_once AADSSO_PLUGIN_DIR . 'Settings.php';
require_once AADSSO_PLUGIN_DIR . 'AuthorizationHelper.php';

// TODO: Auto-load the (the exceptions at least)
require_once AADSSO_PLUGIN_DIR . 'lib/php-jwt/Authentication/JWT.php';
require_once AADSSO_PLUGIN_DIR . '/lib/php-jwt/Exceptions/BeforeValidException.php';
require_once AADSSO_PLUGIN_DIR . '/lib/php-jwt/Exceptions/ExpiredException.php';
require_once AADSSO_PLUGIN_DIR . '/lib/php-jwt/Exceptions/SignatureInvalidException.php';

class AADSSO {

	/**
	 * @var string The URL to redirect to after signing in.
	 */
	public static $redirect_uri = '';

	/**
	 * @var string The URL to redirect to after signing out (of AAD, not WP).
	 */
	public static $logout_redirect_uri = '';

	public static $redirect_after_login_query_arg = 'aad_sso_return_to_page_post_login';

	static $instance = false;
	private $settings = null;

	const NONCE_NAME = 'aad-sso-nonce';

	public function __construct() {
		$this->settings = AADSSO_Settings::load_settings();

		// Set the redirect urls
		self::$redirect_uri = wp_login_url();
		self::$logout_redirect_uri = wp_login_url();

		// If plugin is not configured, we shouldn't proceed.
		if ( ! $this->plugin_is_configured() ) {
			return;
		}

		// The authenticate filter
		add_filter( 'authenticate', array( $this, 'authenticate' ), 1, 3 );

		// Some debugging locations

		// Add the <style> element to the login page
		add_action( 'login_enqueue_scripts', array( $this, 'printLoginCss' ) );

		// Add the link to the organization's sign-in page
		add_action( 'login_form', array( $this, 'printLoginLink' ) );

		add_action( 'login_init', array( $this, 'maybeBypassLogin' ) );
	}

	/**
	 * Determine if required plugin settings are stored
	 *
	 * @return bool Whether plugin is configured
	 */
	public function plugin_is_configured() {
		return isset( $this->settings->client_id, $this->settings->base_uri ) && $this->settings->client_id && $this->settings->base_uri;
	}

	public static function get_instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Decides wether or not to bypass the login form and forward straight to AAD login
	 */
	public function maybeBypassLogin() {
		$bypass = apply_filters( 'aad_auto_forward_login', false );

		/*
		 * If the user is attempting to logout AND the auto-forward to AAD
		 * login is set then we need to ensure we do not auto-forward the user and get
		 * them stuck in an infinite logout loop.
		 */
		if ( $this->wantsToLogin() && $bypass && ! isset( $_GET['code'] ) ) {
			wp_redirect( $this->getLoginUrl() );
			die();
		}
	}

	/**
	 * Checks to determine if the user wants to login on wp-login
	 *
	 * This function mostly exists to cover the exceptions to login
	 * that may exist as other parameters to $_GET[action] as $_GET[action]
	 * does not have to exist. By default WordPress assumes login if an action
	 * is not set, however this may not be true, as in the case of logout
	 * where $_GET[loggedout] is instead set
	 *
	 * @return boolean
	 */
	private function wantsToLogin() {
		$wants_to_login = false;
		// Cover default WordPress behavior
		$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';
		// And now the exceptions
		$action = isset( $_GET['loggedout'] ) ? 'loggedout' : $action;
		if ( 'login' == $action ) {
			$wants_to_login = true;
		}
		return $wants_to_login;
	}

	function authenticate( $user, $username, $password ) {

		// Don't re-authenticate if already authenticated
		if ( is_a( $user, 'WP_User' ) ) {
			return $user;
		}
		if ( ! isset( $_GET['id_token'] ) ) {

			if ( isset( $_GET['error'] ) ) {
				// The attempt to get an authorization code failed (i.e., the reply from the STS was "No.")
				return new WP_Error( $_GET['error'], sprintf( 'ERROR: Access denied to Azure Active Directory. %s', $_GET['error_description'] ) );
			}

			return $user;
		}

		try {
			AADSSO_AuthorizationHelper::$base_uri = $this->settings->base_uri;
			$jwt = AADSSO_AuthorizationHelper::validate_id_token( $_GET['id_token'] );
		} catch ( Exception $e ) {
			return new WP_Error( 'invalid_id_token' , sprintf( 'ERROR: Invalid id_token. %s', $e->getMessage() ) );
		}

		if ( ! wp_verify_nonce( $jwt->nonce, self::NONCE_NAME ) ) {
			return new WP_Error( 'nonce_fail', sprintf( 'NONCE_NAME mismatch. Expecting %s', self::NONCE_NAME ) );
		}

		if ( $jwt->aud != $this->settings->client_id ) {
			//	Need to check [aud] is the same as the client id
			return new WP_Error( 'client_id_mismatch', sprintf( 'ERROR: aud ( %s ) does not match Client ID', $jwt->aud ) );
		}

		if ( ( strpos( $jwt->iss, 'sts.windows.net' ) == false )  && ( strpos( $jwt->iss, 'sts.windows-ppe.net' ) == false ) )  {
			//	[iss] contains sts.windows.net or sts.windows-ppe.net
			return new WP_Error( 'issuer_mismatch', sprintf( 'ERROR: Issuer was %s, expected windows.net', $jwt->iss ) );
		}

		if ( (int) $jwt->iat > (int) time() ) {
			//	[iat] must not be in the future
			return new WP_Error( 'issuing_time_error', sprintf( 'ERROR: Account must be issued in the past, was issued at %s.', $jwt->iat ) );
		}

		if ( (int) $jwt->exp <= (int) time() ) {
			//	[exp] must not be in the past
			return new WP_Error( 'issuing_is_expired', sprintf( 'ERROR: Account has expired on %s', $jwt->exp ) );
		}

		// Try to find an existing user in WP with the ObjectId of the currect AAD user
		$user = $this->get_user_by_aad_id( $jwt->altsecid );

		// If we have a user, log them in
		if ( ! empty( $user ) && is_a( $user, 'WP_User' ) ) {
			// At this point, we have an authorization code, an access token and the user exists in WordPress.
			$user = apply_filters( 'aad_sso_found_user', $user, $jwt );

			return $user;
		}

		/*
		 * No user found. Now decide if we are allowed to create a new
		 * user or not. Will use the WordPress setting from Settings > General
		 */
		$reg_open = get_option( 'users_can_register' );
		$override_reg = apply_filters( 'aad_override_user_registration', $this->settings->override_user_registration );

		if ( ! $reg_open && ! $override_reg ) {
			return new WP_Error( 'user_not_registered', sprintf( 'ERROR: The authenticated user %s is not a registered user in this blog.', $jwt->email ) );
		}

		if ( empty( $jwt->email ) ) {
			return new WP_Error( 'user_not_registered', sprintf( 'ERROR: no email present for user %s.', $jwt->altsecid ) );
		}

		$username = explode( '@', $jwt->email );
		$username = apply_filters( 'aad_sso_login_username', $username[0], $jwt );

		$username = get_user_by( 'login', $username )
			? 'aadsso-'. sanitize_text_field( $jwt->altsecid )
			: $username;

		// Setup the minimum required user data
		$userdata = array(
			'user_login'   => wp_slash( $username ),
			'user_email'   => wp_slash( $jwt->email ),
			'user_pass'    => wp_generate_password( 20, true ),
			'first_name'   => isset( $jwt->given_name ) ? esc_html( $jwt->given_name ) : '',
			'last_name'    => isset( $jwt->family_name ) ? esc_html( $jwt->family_name ) : '',
			'role'         => $this->settings->default_wp_role ? $this->settings->default_wp_role : 'subscriber',
		);

		$userdata['display_name'] = $userdata['nickname'] = $userdata['first_name'] && $userdata['last_name']
			? $userdata['first_name'] . ' ' . $userdata['last_name']
			: $userdata['first_name'];

		// Allow user-creation override
		$user = apply_filters( 'aad_sso_new_user_override', null, $userdata, $jwt );

		// If we have a user, log them in
		if ( ! empty( $user ) && is_a( $user, 'WP_User' ) ) {

			// At this point, the user exists in WordPress.
			$user = apply_filters( 'aad_sso_found_user', $user, $jwt );

			return $user;
		}

		$new_user_id = wp_insert_user( $userdata );

		if ( is_wp_error( $new_user_id ) ) {
			return $new_user_id;
		}

		// update usermeta so we know who the user is next time
		update_user_meta( $new_user_id, '_aad_sso_altsecid', sanitize_text_field( $jwt->altsecid ) );
		$user = new WP_User( $new_user_id );

		// @todo do_action new_user
		$user = apply_filters( 'aad_sso_new_user', $user, $jwt );

		return $user;
	}

	public function get_user_by_aad_id( $aad_id ) {
		global $wpdb;
		/*
		 * We need to do this with a normal SQL query, as get_users()
		 * seems to behave unexpectedly in a multisite environment
		 */
		$query = "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = '_aad_sso_altsecid' AND meta_value = %s";
		$query = $wpdb->prepare( $query, sanitize_text_field( $aad_id ) );
		$user_id = $wpdb->get_var( $query );
		$user = $user_id ? get_user_by( 'id', $user_id ) : false;

		return $user;
	}

	function getLoginUrl() {
		$redirect_uri = self::redirect_uri( __FUNCTION__ );
		$nonce = wp_create_nonce( self::NONCE_NAME );
		return trailingslashit( $this->settings->base_uri ) .'oauth2/authorize?client_id='. $this->settings->client_id .'&response_mode=query&response_type=code+id_token&redirect_uri='. $redirect_uri .'&nonce='. $nonce;
	}

	function getLogoutUrl() {
		$logout_uri = self::logout_redirect_uri( __FUNCTION__ );
		return trailingslashit( $this->settings->base_uri ) .'oauth2/logout?post_logout_redirect_uri='. $logout_uri;
	}

	/*** View ****/

	function printLoginCss() {
		wp_enqueue_style( 'aad-sso-wordpress', AADSSO_PLUGIN_URL . '/login.css' );
	}

	public function printLoginLink() {
		echo $this->getLoginLink();
	}

	function getLoginLink() {
		$login_url = $this->getLoginUrl();
		$logout_url = $this->getLogoutUrl();
		$org_display_name = $this->settings->org_display_name;

		$html = <<<EOF
			<p class="aadsso-login-form-text">
				<a href="%s">Sign in with your %s account</a><br />
				<a class="dim" href="%s">Sign out</a>
			</p>
EOF;
		$html = sprintf( $html, $login_url, htmlentities( $org_display_name ), $logout_url );
		return apply_filters( 'aad_sso_login_link', $html, $login_url, $logout_url, $org_display_name );
	}

	public static function redirect_uri( $context = '' ) {
		return apply_filters( 'aad_sso_redirect_uri', self::$redirect_uri, $context );
	}

	public static function logout_redirect_uri( $context = '' ) {
		return apply_filters( 'aad_sso_logout_redirect_uri', self::$logout_redirect_uri, $context );
	}

} // end class

$aadsso = AADSSO::get_instance();
