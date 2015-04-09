<?php

class AADSSO_GraphHelper {
	public static $ch;
	public static $settings;
	public static $token;
	public static $tenant_id;

	// TODO: validation if tenat_id is not set
	public static function getResourceUrl() {
		return self::$settings->resourceURI . '/' . self::$tenant_id;
	}

	public static function getUsers() {
		$url = self::getResourceUrl() . '/users/' . '?api-version=' . self::$settings->graphVersion;
		return self::getRequest( $url );
	}

	public static function getUserMemberOf( $id ) {
		$url = self::getResourceUrl() . '/users/' . $id . '/$links/memberOf?api-version=' . self::$settings->graphVersion;
		return self::getRequest( $url );
	}

	public static function getGroups() {
		return self::getRequest( self::getResourceUrl() . '/groups?api-version=' . self::$settings->graphVersion );
	}

	public static function userCheckMemberGroups( $id, $group_ids ) {
		$group_ids = array_filter( $group_ids ); //remove empty elements
		$url = self::getResourceUrl() . '/users/' . $id . '/checkMemberGroups?api-version=' . self::$settings->graphVersion;
		return self::postRequest( $url, array('groupIds' => $group_ids) );
	}

	public static function getUser( $id ) {
		$url = self::getResourceUrl() . '/users/' . $id . '?api-version=' . self::$settings->graphVersion;
		return self::getRequest( $url );
	}

	public static function updateUser( $id, $data ){
		return self::patchRequest(
				self::getResourceUrl() . '/users/' . $id . '?api-version=' . self::$settings->graphVersion, $data);
	}

	public static function getMe(){
		return self::getRequest( self::getResourceUrl() . '/me' . '?api-version=' . self::$settings->graphVersion );
	}

	public static function updateMe( $data ){
		return self::patchRequest(
				self::getResourceUrl() . '/me' . '?api-version=' . self::$settings->graphVersion, $data);
	}

	public static function getRequest( $url ) {
		return self::request( 'GET', $url );
	}

	public static function patchRequest( $url, $data ) {
		$response = self::postRequest( $url, $data );

		// Legacy hack
		$payload = json_encode( $data );
		$_SESSION['last_request'] = array('method' => 'PATCH', 'url' => $url, 'payload' => $payload);

		return $response;
	}

	public static function postRequest( $url, $data ) {
		return self::request( 'POST', $url, $data );
	}

	public static function request( $method, $url, $data = '' ) {

		$headers = self::AddRequiredHeadersAndSettings();

		if ( is_wp_error( $headers ) ) {
			return $headers;
		}

		$args = array(
			'headers' => $headers,
			'method' => $method,
		);

		$payload = '';

		if ( $data ) {
			$payload = json_encode( $data );
			$args['body'] = $payload;
		}

		$response = wp_remote_post( $url, $args );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$output = json_decode( wp_remote_retrieve_body( $response ) );

		$_SESSION['last_request'] = array( 'method' => $method, 'url' => $url, 'payload' => $payload );
		$_SESSION['last_request']['response'] = $output;

		return $output;
	}

	// Add required headers like authorization header, service version etc.
	public static function AddRequiredHeadersAndSettings() {

		if ( ! isset( $_SESSION['token_type'], $_SESSION['access_token'] ) ) {
			return new WP_Error( 'session_data_missing', 'ERROR: Session data missing (token_type, and/or access_token).' );
		}

		return array(
			'Authorization' => $_SESSION['token_type'] . ' ' . $_SESSION['access_token'],
			'Accept'        => 'application/json;odata=minimalmetadata',
			'Content-Type'  => 'application/json;odata=minimalmetadata',
			'Prefer'        => 'return-content',
		);
	}

}
