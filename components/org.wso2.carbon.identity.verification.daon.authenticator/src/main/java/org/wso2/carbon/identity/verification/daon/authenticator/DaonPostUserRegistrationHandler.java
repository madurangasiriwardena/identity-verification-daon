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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationException;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdVClaim;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.THREAD_LOCAL_DAON_IDVP_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.THREAD_LOCAL_DAON_VERIFIED_CLAIMS;

/**
 * Event handler that persists Daon TrustX verified claim data to the IDV_CLAIM table after a user
 * is provisioned during the sign-up flow.
 *
 * <p>The {@link DaonAuthenticator} cannot write to IDV_CLAIM directly because the USER_ID does not
 * exist at that point. Instead it stores the verified claims in
 * {@link IdentityUtil#threadLocalProperties} (a request-scoped ThreadLocal). This handler reads
 * those values in the POST_ADD_USER event — which fires in the same request thread after JIT
 * provisioning creates the user — and persists them with the real USER_ID.
 *
 * <p>Thread-local cleanup is always performed in a finally block to prevent data leaking into
 * subsequent requests that reuse the same pooled thread.
 */
public class DaonPostUserRegistrationHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(DaonPostUserRegistrationHandler.class);

    @Override
    public String getName() {

        return "DaonPostUserRegistrationHandler";
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        if (messageContext instanceof org.wso2.carbon.identity.event.bean.IdentityEventMessageContext) {
            org.wso2.carbon.identity.event.bean.IdentityEventMessageContext eventMessageContext =
                    (org.wso2.carbon.identity.event.bean.IdentityEventMessageContext) messageContext;
            return IdentityEventConstants.Event.POST_ADD_USER.equals(
                    eventMessageContext.getEvent().getEventName());
        }
        return false;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> threadLocalProps = IdentityUtil.threadLocalProperties.get();
        try {
            @SuppressWarnings("unchecked")
            Map<String, String> verifiedClaims =
                    (Map<String, String>) threadLocalProps.get(THREAD_LOCAL_DAON_VERIFIED_CLAIMS);

            if (verifiedClaims == null || verifiedClaims.isEmpty()) {
                return;
            }

            String idvpId = (String) threadLocalProps.get(THREAD_LOCAL_DAON_IDVP_ID);
            if (idvpId == null) {
                return;
            }

            String userId = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.USER_ID);
            int tenantId = (int) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_ID);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Persisting Daon verified claims for user: " + userId
                        + ", idvpId: " + idvpId + ", claims: " + verifiedClaims.keySet());
            }

            List<IdVClaim> idVClaims = buildIdVClaims(userId, idvpId, verifiedClaims);
            DaonAuthenticatorDataHolder.getIdentityVerificationManager()
                    .addIdVClaims(userId, idVClaims, tenantId);

        } catch (IdentityVerificationException e) {
            throw new IdentityEventException("Error persisting Daon verified claims after user registration.", e);
        } finally {
            threadLocalProps.remove(THREAD_LOCAL_DAON_VERIFIED_CLAIMS);
            threadLocalProps.remove(THREAD_LOCAL_DAON_IDVP_ID);
        }
    }

    private List<IdVClaim> buildIdVClaims(String userId, String idvpId,
                                           Map<String, String> verifiedClaims) {

        List<IdVClaim> idVClaims = new ArrayList<>();
        String completedAt = Instant.now().toString();

        for (Map.Entry<String, String> entry : verifiedClaims.entrySet()) {
            IdVClaim claim = new IdVClaim();
            claim.setUuid(UUID.randomUUID().toString());
            claim.setUserId(userId);
            claim.setClaimUri(entry.getKey());
            claim.setIdVPId(idvpId);
            claim.setIsVerified(true);
            claim.setClaimValue(entry.getValue());

            Map<String, Object> metadata = new HashMap<>();
            metadata.put(DaonConstants.DAON_FLOW_STATUS,
                    DaonConstants.VerificationFlowStatus.COMPLETED.getStatus());
            metadata.put(DaonConstants.DAON_VERIFICATION_STATUS,
                    DaonConstants.DaonVerificationStatus.VERIFIED.getStatus());
            metadata.put(DaonConstants.DAON_COMPLETED_AT, completedAt);
            claim.setMetadata(metadata);

            idVClaims.add(claim);
        }
        return idVClaims;
    }
}
