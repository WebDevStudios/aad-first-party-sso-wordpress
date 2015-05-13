<?php

// A class that provides authorization token for apps that need to access Azure Active Directory Graph Service.
class AADSSO_AuthorizationHelper {

    /**
     * @var string The OpenID Connect api endpoint
     */
    public static $base_uri = 'https://login.windows.net/common/';

    /**
     * @var string The OpenID Connect JSON Web Key Set endpoint.
     */
    public static $keys_endpoint = 'discovery/keys';

    // Currently, only RS256 is allowed and expected from AAD.
    private static $allowed_algorithms = array('RS256');

    public static function validate_id_token( $id_token ) {

        $jwt = null;
        $lastException = null;

        // TODO: cache the keys
        $discovery = json_decode( file_get_contents( self::$base_uri . self::$keys_endpoint ) );

        if ($discovery->keys == null) {
            throw new DomainException('base_uri + keys_endpoint does not contain the keys attribute');
        }

        foreach ($discovery->keys as $key) {
            try {
                if ($key->x5c == null) {
                    throw new DomainException('key does not contain the x5c attribute');
                }

                $key_der = $key->x5c[0];

                // Per section 4.7 of the current JWK draft [1], the 'x5c' property will be the DER-encoded value
                // of the X.509 certificate. PHP's openssl functions all require a PEM-encoded value.
                $key_pem = chunk_split($key_der, 64, "\n");
                $key_pem = "-----BEGIN CERTIFICATE-----\n".$key_pem."-----END CERTIFICATE-----\n";

                // This throws exception if the id_token cannot be validated.

                $jwt = JWT::decode( $id_token, $key_pem, self::$allowed_algorithms);
                break;
            } catch (Exception $e) {
                $lastException = $e;
            }
        }

        if ($jwt == null) {
            throw $lastException;
        }

        return $jwt;
    }
}
