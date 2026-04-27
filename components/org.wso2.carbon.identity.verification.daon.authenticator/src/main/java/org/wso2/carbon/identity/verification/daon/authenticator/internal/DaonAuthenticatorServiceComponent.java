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

package org.wso2.carbon.identity.verification.daon.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.extension.identity.verification.mgt.IdentityVerificationManager;
import org.wso2.carbon.extension.identity.verification.provider.IdVProviderManager;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.verification.daon.authenticator.DaonAuthenticator;
import org.wso2.carbon.identity.verification.daon.authenticator.DaonPostUserRegistrationHandler;

/**
 * OSGi service component for the Daon TrustX federated authenticator.
 */
@Component(
        name = "daon.identity.authenticator",
        immediate = true)
public class DaonAuthenticatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(DaonAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            ctxt.getBundleContext().registerService(
                    ApplicationAuthenticator.class.getName(), new DaonAuthenticator(), null);
            ctxt.getBundleContext().registerService(
                    AbstractEventHandler.class.getName(), new DaonPostUserRegistrationHandler(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("DaonAuthenticator bundle activated successfully.");
            }
        } catch (Throwable e) {
            LOG.fatal("Error while activating DaonAuthenticator bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("DaonAuthenticator bundle is deactivated.");
        }
    }

    @Reference(
            name = "IdVProviderManager",
            service = IdVProviderManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdVProviderManager")
    protected void setIdVProviderManager(IdVProviderManager idVProviderManager) {

        DaonAuthenticatorDataHolder.setIdVProviderManager(idVProviderManager);
    }

    protected void unsetIdVProviderManager(IdVProviderManager idVProviderManager) {

        DaonAuthenticatorDataHolder.setIdVProviderManager(null);
    }

    @Reference(
            name = "IdentityVerificationManager",
            service = IdentityVerificationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityVerificationManager")
    protected void setIdentityVerificationManager(IdentityVerificationManager identityVerificationManager) {

        DaonAuthenticatorDataHolder.setIdentityVerificationManager(identityVerificationManager);
    }

    protected void unsetIdentityVerificationManager(IdentityVerificationManager identityVerificationManager) {

        DaonAuthenticatorDataHolder.setIdentityVerificationManager(null);
    }
}
