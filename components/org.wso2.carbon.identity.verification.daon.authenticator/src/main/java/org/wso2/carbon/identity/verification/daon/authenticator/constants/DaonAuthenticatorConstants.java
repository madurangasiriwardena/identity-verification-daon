/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.verification.daon.authenticator.constants;

/**
 * Constants for the Daon TrustX federated authenticator.
 */
public class DaonAuthenticatorConstants {

    private DaonAuthenticatorConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "DaonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Daon TrustX";

    /**
     * The authenticator property key that holds the Daon IdVP UUID.
     * Admins set this to the UUID of the already-configured Daon Identity Verification Provider.
     */
    public static final String DAON_IDVP_ID = "daon_idvp_id";

    /**
     * The /commonauth redirect URI used for the authentication flow.
     * Overrides the IdVP-configured redirect_uri which points to the API callback.
     */
    public static final String COMMON_AUTH_ENDPOINT = "/commonauth";

    /**
     * Thread-local keys used to pass verified claim data from the authenticator
     * to the post-user-registration event handler within the same request thread.
     */
    public static final String THREAD_LOCAL_DAON_VERIFIED_CLAIMS = "DAON_IDV_CLAIMS";
    public static final String THREAD_LOCAL_DAON_IDVP_ID = "DAON_IDV_IDVP_ID";

    /**
     * Query parameters on the OIDC callback request.
     */
    public static final String PARAM_CODE = "code";
    public static final String PARAM_STATE = "state";
    public static final String PARAM_SESSION_STATE = "session_state";

    // Configurable property keys exposed in the admin UI
    public static final String DAON_AUTH_ENDPOINT_PARAM = "daonAuthorizationEndpoint";
    public static final String DAON_TOKEN_ENDPOINT_PARAM = "daonTokenEndpoint";

    // Default Daon (Keycloak) endpoints — configurable via authenticator properties
    public static final String DAON_OAUTH_ENDPOINT =
            "https://wso2.oak.trustx.com/auth/realms/wso2/protocol/openid-connect/auth";
    public static final String DAON_TOKEN_ENDPOINT =
            "https://wso2.oak.trustx.com/auth/realms/wso2/protocol/openid-connect/token";

    // OIDC claims request parameter sent to the Daon authorization endpoint.
    // Requests all IDV claims inside the id_token using the verified_claims structure.
    public static final String DAON_CLAIMS_REQUEST_JSON =
            "{\"id_token\":{\"verified_claims\":{" +
                    "\"verification\":{\"trust_framework\":\"daon-identify-1\"}," +
                    "\"claims\":{" +
                    "\"family_name_and_given_name\":null," +
                    "\"birthdate\":null," +
                    "\"nationality\":null," +
                    "\"nationality_code\":null," +
                    "\"given_name\":null," +
                    "\"family_name\":null," +
                    "\"first_family_name\":null," +
                    "\"second_family_name\":null," +
                    "\"document_type\":null," +
                    "\"document_classification\":null," +
                    "\"document_date_of_expiry\":null," +
                    "\"document_number\":null," +
                    "\"document_personal_number\":null," +
                    "\"address\":null" +
                    "}}}}";


    // Claim dialect URI for Daon-specific claims
    public static final String CLAIM_DIALECT_URI = "http://wso2.org/daon/claims";

    // Identity verification provider ID registered in WSO2 IS for Daon
    public static final String DAON_IDV_PROVIDER_ID = "DAON";
    public static final String DAON_IDV_ID = "89463071-0c22-46ad-aed5-c43d11682ab3";

    // Top-level JWT claim field names
    public static final String JWT_SUBJECT_CLAIM = "sub";
    public static final String JWT_VERIFIED_CLAIMS_OBJECT = "verifiedClaims";
    public static final String JWT_CLAIMS_OBJECT = "claims";

    // Daon claim keys inside the "claims" JWT object
    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_ADDRESS_FORMATTED = "formatted";

    public static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";

    // IS identity claim used to lock a user account
    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
}
