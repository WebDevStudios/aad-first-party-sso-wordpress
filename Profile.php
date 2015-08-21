<?php
/**
 * All profile settings and button for linking WordPress account
 *
 * @since   0.2.1
 * @package AADSSO
 */
class AADSSO_Profile {

	/**
	 * A single instance of this class.
	 * @var null|AADSSO_Profile
	 */
	protected static $single_instance = null;

	/**
	 * User id of the currently logged-in user
	 *
	 * @var integer
	 */
	public $user_to_keep = 0;

	/**
	 * The AADSSO instance
	 *
	 * @var null|AADSSO
	 */
	public $aadsso = null;

	/**
	 * The AADSSO_Settings instance
	 *
	 * @var null|AADSSO_Settings
	 */
	public $settings = null;

	/**
	 * Creates or returns an instance of this class.
	 * @since  0.2.1
	 * @return AADSSO_Profile A single instance of this class.
	 */
	public static function get_instance( $aadsso = null ) {
		if ( null === self::$single_instance ) {
			if ( ! $aadsso ) {
				throw new Exception( 'AADSSO_Profile::get_instance requires the AADSSO instance to be provided' );
			}
			self::$single_instance = new self( $aadsso );
		}

		return self::$single_instance;
	}

	/**
	 * Object constructor
	 *
	 * @since 0.2.1
	 *
	 * @param null|AADSSO
	 */
	protected function __construct( $aadsso = null ) {
		// Assign properties
		$this->aadsso = is_a( $aadsso, 'AADSSO' ) ? $aadsso : AADSSO::get_instance();
		$this->settings = AADSSO_Settings::get_instance();

		// Add hooks
		add_action( 'init', array( $this, 'init' ) );
	}

	/**
	 * Init hooks
	 * @since  0.2.1
	 * @return null
	 */
	public function init() {

		add_action( 'show_user_profile', array( $this, 'aad_sso_merge_button' ) );
		add_action( 'admin_init', array( $this, 'handle_redirects' ), 9999 );

		// Jump in before and after aad-sso to merge the users (if requested)
		add_filter( 'authenticate', array( $this, 'maybe_cache_user' ), 0 );
		add_filter( 'aad_sso_new_user_override', array( $this, 'maybe_connect_before_create' ), 10, 3 );
		add_filter( 'aad_sso_found_user', array( $this, 'maybe_connect_found_user' ), 10, 2 );
		add_filter( 'authenticate', array( $this, 'catch_errors' ), 2 );

		add_action( 'all_admin_notices', array( $this, 'maybe_user_notice' ) );
	}

	/**
	 * Outputs profile section with AAD account merge button
	 *
	 * @since  0.2.1
	 *
	 * @return null
	 */
	public function aad_sso_merge_button() {
		$user_id = get_current_user_id();

		// If aadsso altsecid, no need to link the account
		if ( get_user_meta( $user_id, $this->aadsso->user_id_meta_key, 1 ) ) {
			return;
		}

		$url = wp_nonce_url( add_query_arg( 'user_id_to_map', $user_id ), 'link-aadsso', 'link-aadsso' );

		?>
		<table class="form-table">
			<tbody>
				<tr id="aadsso-link">
					<th><label><?php _e( 'Link Azure Active Directory Account', 'aad-sso' ); ?></label></th>
					<td>
						<a class="button-secondary" href="<?php echo esc_url( $url ); ?>"><?php printf( __( 'Sign in with your %s account', 'aad-sso' ), $this->settings->org_display_name ); ?></a>
						<?php do_action( 'aad_sso_link_user_description' ); ?>
					</td>
				</tr>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Handles determining if redirects are needed
	 *
	 * @since  0.2.1
	 *
	 * @return null
	 */
	public function handle_redirects() {
		global $pagenow;

		$user_id = get_current_user_id();

		if ( 'profile.php' != $pagenow ) {
			$this->maybe_redirect_to_profile( $user_id );
		} else {
			$this->maybe_redirect_to_profile( $user_id );
			$this->maybe_redirect_to_aad( $user_id );
		}

	}

	/**
	 * Handles determing if a redirect to the profile screen is needed.
	 * Will redirect if the profile was linked successfully or if there was an error.
	 *
	 * @since  0.2.1
	 *
	 * @param  int  $user_id User ID
	 *
	 * @return null
	 */
	public function maybe_redirect_to_profile( $user_id ) {
		foreach ( array( 'aadsso_link_failed', 'aadsso_is_linked' ) as $check_redirect ) {
			if ( ! isset( $_GET[ $check_redirect ] ) && get_user_meta( $user_id, $check_redirect, 1 ) ) {
				wp_redirect( admin_url( 'profile.php?'. $check_redirect ) );
				exit;
			}
		}
	}

	/**
	 * Handles determing if a redirect to the AAD signin experience is needed
	 *
	 * @since  0.2.1
	 *
	 * @param  int  $user_id User ID
	 *
	 * @return null
	 */
	public function maybe_redirect_to_aad( $user_id ) {
		if (
			! isset( $_GET['user_id_to_map'], $_GET['link-aadsso'] )
			|| $_GET['user_id_to_map'] != $user_id
			|| ! wp_verify_nonce( $_GET['link-aadsso'], 'link-aadsso' )
		) {
			return;
		}

		update_user_meta( $user_id, 'is_aadsso_linking', 'true' );
		wp_redirect( $this->aadsso->getLoginUrl() );
		exit;
	}

	/**
	 * Handles storing user id to an object property if the conditions are met for merging
	 * Hooked to 'authenticate', 0
	 *
	 * @since  0.2.1
	 *
	 * @param  mixed  $user User object or WP_Error
	 *
	 * @return mixed        User object or WP_Error
	 */
	public function maybe_cache_user( $user ) {
		$user_id = get_current_user_id();

		if (
			$user_id
			&& $this->is_redirect_from_aad()
			&& ! get_user_meta( $user_id, $this->aadsso->user_id_meta_key, 1 )
			&& get_user_meta( $user_id, 'is_aadsso_linking', 1 )
		) {
			$this->user_to_keep = $user_id;
		}

		return $user;
	}

	/**
	 * Intercept the AADSSO user-creation and instead attach to the user-to-link.
	 * Hooked to 'aad_sso_new_user_override'
	 *
	 * @since  0.2.2
	 *
	 * @param  mixed  $null     Return non-null value to override user-creation
	 * @param  array  $userdata Array of new-user userdata
	 * @param  object $jwt      JWT object
	 *
	 * @return null|WP_User     If we're linking, returns the linked user object
	 */
	public function maybe_connect_before_create( $null, $userdata, $jwt ) {

		if ( ! $this->user_to_keep ) {
			return $null;
		}

		$user = new WP_User( $this->user_to_keep );

		// Stop recursion
		remove_filter( 'aad_sso_found_user', array( $this, 'maybe_connect_found_user' ), 10, 2 );

		return $this->connect_accounts( $user, sanitize_text_field( $jwt->altsecid ), true );
	}

	/**
	 * Handles merging an AAD user with the stored user.
	 * Hooked to 'aad_sso_found_user'.
	 *
	 * @since  0.2.1
	 *
	 * @return mixed User object or WP_Error
	 */
	public function maybe_connect_found_user( $user, $jwt ) {

		if (
			! $this->user_to_keep
			|| $this->user_to_keep == $user->ID
		) {
			return $user;
		}

		return $this->connect_accounts( $user, sanitize_text_field( $jwt->altsecid ) );
	}

	/**
	 * Merges a new AAD user with your existing WP user
	 *
	 * @since  0.2.1
	 *
	 * @param  WP_User $user_to_link New WP_User object to link existing WP user
	 * @param  string  $aad_sso_id   AADSSO user id
	 * @param  bool    $same_user    If getting a user from maybe_connect_before_create, the user will be the same.
	 *
	 * @return WP_User               The linked user object after merge
	 */
	protected function connect_accounts( $user_to_link, $aad_sso_id, $same_user = false ) {

		$updated = update_user_meta( $this->user_to_keep, $this->aadsso->user_id_meta_key, $aad_sso_id );

		if ( $same_user ) {
			do_action( 'aad_sso_link_user', $user_to_link->ID, $this->user_to_keep, $same_user );
		} else {
			do_action( 'aad_sso_link_users', $user_to_link->ID, $this->user_to_keep, $same_user );
		}

		if ( ! $same_user ) {

			// WordPress User Administration API
			require_once( ABSPATH . 'wp-admin/includes/user.php' );

			$this->reassign_comments( $user_to_link->ID );
			wp_delete_user( $user_to_link->ID, $this->user_to_keep );

		}

		delete_user_meta( $this->user_to_keep, 'is_aadsso_linking' );
		update_user_meta( $this->user_to_keep, 'aadsso_is_linked', 'true' );

		return $same_user ? $user_to_link : get_user_by( 'id', $this->user_to_keep );
	}

	/**
	 * Re-assigns comments from a user about to be deleted to the stored user
	 *
	 * @since  0.2.1
	 *
	 * @param  int  $user_to_delete User ID of user which will be deleted
	 *
	 * @return bool                 Whether comment reassignment was successful
	 */
	protected function reassign_comments( $user_to_delete ) {
		global $wpdb;

		$result = $wpdb->update(
			$wpdb->comments,
			array(
				'user_id' => $this->user_to_keep,
			),
			array(
				'user_id' => $user_to_delete,
			),
			array( '%d' ),
			array( '%d' )
		);

		return false === $result ? false : true;
	}

	/**
	 * If there was an error during linking, save to user-meta for later output
	 * Hooked to 'authenticate', 2
	 *
	 * @since  0.2.2
	 *
	 * @param  WP_User|WP_Error $user User object or WP_Error object
	 *
	 * @return WP_User|WP_Error       User object or WP_Error object
	 */
	public function catch_errors( $user ) {
		if ( $this->user_to_keep && is_wp_error( $user ) ) {
			update_user_meta( $this->user_to_keep, 'aadsso_link_failed', $user->get_error_messages() );
		}

		return $user;
	}

	/**
	 * Determines if a merge-success or error message should be displayed
	 * Hooked to 'all_admin_notices', 2
	 *
	 * @since  0.2.1
	 *
	 * @return null
	 */
	public function maybe_user_notice() {
		if ( isset( $_GET['aadsso_link_failed'] ) ) {
			$this->maybe_error_notice();
		}
		if ( isset( $_GET['aadsso_is_linked'] ) ) {
			$this->maybe_success_notice();
		}
	}

	/**
	 * Determines if a merge-fail message should be displayed
	 *
	 * @since  0.2.2
	 *
	 * @return null
	 */
	public function maybe_error_notice() {
		$user_id = get_current_user_id();

		$errors = get_user_meta( $user_id, 'aadsso_link_failed', 1 );

		if ( ! $errors ) {
			return;
		}

		if ( is_array( $errors ) ) {
			$errors = count( $errors ) > 1 ? '<ul><li>'. implode( '</li><li>', $errors ) . '</li></ul>' : end( $errors );
		}

		echo '<div id="message" class="error"><p>' . sprintf( __( '<strong>ERROR:</strong> %s', 'aad-sso' ), $errors ) . '</p></div>';

		delete_user_meta( $user_id, 'aadsso_link_failed' );
	}

	/**
	 * Determines if a merge-success message should be displayed
	 *
	 * @since  0.2.2
	 *
	 * @return null
	 */
	public function maybe_success_notice() {
		$user_id = get_current_user_id();

		if ( ! get_user_meta( $user_id, 'aadsso_is_linked', 1 ) ) {
			return;
		}

		echo '<div id="message" class="updated"><p>' . __( 'Success, your profile has been linked to your Azure Active Directory account.', 'aad-sso' ) . '</p></div>';

		delete_user_meta( $user_id, 'aadsso_is_linked' );
	}

	/**
	 * Determines if current request is a redirect from AAD
	 *
	 * @since  0.2.1
	 *
	 * @return boolean Whether current request is a redirect from AAD
	 */
	protected function is_redirect_from_aad() {
		return isset( $_GET['code'], $_GET['session_state'], $_GET['id_token'] );
	}

}
