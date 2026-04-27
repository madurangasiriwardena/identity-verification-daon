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

package org.wso2.carbon.identity.verification.daon.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.verification.provider.exception.IdVProviderMgtException;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVConfigProperty;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVProvider;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.COMMON_AUTH_ENDPOINT;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_IDVP_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_CODE;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_STATE;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.THREAD_LOCAL_DAON_IDVP_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.THREAD_LOCAL_DAON_VERIFIED_CLAIMS;

/**
 * Daon TrustX federated authenticator.
 *
 * <p>Initiates an OIDC Authorization Code flow against the Daon TrustX tenant configured in the
 * referenced Daon IdVP. On callback, extracts verified identity claims from the ID token and stores
 * them in a thread-local for deferred persistence by {@link DaonPostUserRegistrationHandler}.
 */
public class DaonAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(DaonAuthenticator.class);
    private static final long serialVersionUID = 1L;

    @Override
    public String getName() {

        return DaonAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return DaonAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return StringUtils.isNotBlank(request.getParameter(PARAM_CODE))
                && StringUtils.isNotBlank(request.getParameter(PARAM_STATE));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(PARAM_STATE);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String idvpId = authenticatorProperties.get(DAON_IDVP_ID);
        if (StringUtils.isBlank(idvpId)) {
            throw new AuthenticationFailedException("Authenticator property '" + DAON_IDVP_ID + "' is not configured.");
        }

        int tenantId = getTenantId(context);
        IdVProvider idVProvider = resolveIdVProvider(idvpId, tenantId);
        Map<String, String> configMap = extractConfigMap(idVProvider);
        List<String> daonClaimNames = new ArrayList<>(idVProvider.getClaimMappings().values());

        String state = context.getContextIdentifier();
        String redirectUri = buildCommonAuthRedirectUri(request);
        configMap.put(DaonConstants.REDIRECT_URI, redirectUri);

        try {
            String authorizationUrl = DaonAPIClient.buildAuthorizationUrl(configMap, state, daonClaimNames);
            response.sendRedirect(authorizationUrl);
        } catch (DaonServerException e) {
            throw new AuthenticationFailedException("Failed to build Daon authorization URL.", e);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to Daon authorization URL.", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        String code = request.getParameter(PARAM_CODE);
        String state = request.getParameter(PARAM_STATE);

        if (!context.getContextIdentifier().equals(state)) {
            throw new AuthenticationFailedException("State parameter mismatch. Potential CSRF attack.");
        }

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String idvpId = authenticatorProperties.get(DAON_IDVP_ID);
        int tenantId = getTenantId(context);

        IdVProvider idVProvider = resolveIdVProvider(idvpId, tenantId);
        Map<String, String> configMap = extractConfigMap(idVProvider);
        String redirectUri = buildCommonAuthRedirectUri(request);
        configMap.put(DaonConstants.REDIRECT_URI, redirectUri);

        JSONObject idTokenClaims;
        try {
            JSONObject tokenResponse = DaonAPIClient.exchangeCodeForTokens(configMap, code);
            String idToken = tokenResponse.optString(DaonConstants.ID_TOKEN);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon token exchange successful. Parsing ID token.");
            }
            idTokenClaims = DaonAPIClient.parseIdToken(idToken);
        } catch (DaonClientException | DaonServerException e) {
            throw new AuthenticationFailedException("Failed to exchange authorization code for tokens.", e);
        }

        JSONObject verifiedClaimsContainer = idTokenClaims.optJSONObject(DaonConstants.VERIFIED_CLAIMS_ID_TOKEN);
        JSONObject verifiedClaimValues = verifiedClaimsContainer != null
                ? verifiedClaimsContainer.optJSONObject(DaonConstants.CLAIMS_PARAM) : null;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Daon verified claim values from ID token: " + verifiedClaimValues);
        }

        Map<String, String> claimMappings = idVProvider.getClaimMappings();
        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        Map<String, String> verifiedClaimsForStorage = new HashMap<>();

        for (Map.Entry<String, String> entry : claimMappings.entrySet()) {
            String wso2ClaimUri = entry.getKey();
            String daonClaimName = entry.getValue();
            if (verifiedClaimValues != null && verifiedClaimValues.has(daonClaimName)) {
                String claimValue = verifiedClaimValues.optString(daonClaimName);
                ClaimMapping claimMapping = ClaimMapping.build(wso2ClaimUri, wso2ClaimUri, null, false);
                userAttributes.put(claimMapping, claimValue);
                verifiedClaimsForStorage.put(wso2ClaimUri, claimValue);
            }
        }

        String subject = idTokenClaims.optString("preferred_username",
                idTokenClaims.optString("sub", "daon-user"));
        AuthenticatedUser authenticatedUser = AuthenticatedUser
                .createFederateAuthenticatedUserFromSubjectIdentifier(subject);
        authenticatedUser.setUserAttributes(userAttributes);
        context.setSubject(authenticatedUser);

        storeVerifiedClaimsInThreadLocal(verifiedClaimsForStorage, idvpId);
    }

    private void storeVerifiedClaimsInThreadLocal(Map<String, String> verifiedClaims, String idvpId) {

        Map<String, Object> threadLocalProps = IdentityUtil.threadLocalProperties.get();
        threadLocalProps.put(THREAD_LOCAL_DAON_VERIFIED_CLAIMS, verifiedClaims);
        threadLocalProps.put(THREAD_LOCAL_DAON_IDVP_ID, idvpId);
    }

    private IdVProvider resolveIdVProvider(String idvpId, int tenantId) throws AuthenticationFailedException {

        try {
            IdVProvider idVProvider = DaonAuthenticatorDataHolder.getIdVProviderManager()
                    .getIdVProvider(idvpId, tenantId);
            if (idVProvider == null || !idVProvider.isEnabled()) {
                throw new AuthenticationFailedException(
                        "Daon IdVP with ID '" + idvpId + "' not found or is disabled.");
            }
            return idVProvider;
        } catch (IdVProviderMgtException e) {
            throw new AuthenticationFailedException("Error resolving Daon IdVP with ID: " + idvpId, e);
        }
    }

    private Map<String, String> extractConfigMap(IdVProvider idVProvider) {

        Map<String, String> configMap = new HashMap<>();
        IdVConfigProperty[] properties = idVProvider.getIdVConfigProperties();
        if (properties != null) {
            for (IdVConfigProperty property : properties) {
                configMap.put(property.getName(), property.getValue());
            }
        }
        return configMap;
    }

    private String buildCommonAuthRedirectUri(HttpServletRequest request) {

        return request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()
                + COMMON_AUTH_ENDPOINT;
    }

    private int getTenantId(AuthenticationContext context) {

        try {
            return IdentityTenantUtil.getTenantId(context.getTenantDomain());
        } catch (Exception e) {
            return -1234;
        }
    }
}
