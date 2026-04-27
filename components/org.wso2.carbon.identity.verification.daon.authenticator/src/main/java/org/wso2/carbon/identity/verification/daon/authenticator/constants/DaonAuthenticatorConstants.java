/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
}
