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

import org.wso2.carbon.extension.identity.verification.mgt.IdentityVerificationManager;
import org.wso2.carbon.extension.identity.verification.provider.IdVProviderManager;

/**
 * Service holder for the Daon TrustX authenticator OSGi bundle.
 */
public class DaonAuthenticatorDataHolder {

    private static IdVProviderManager idVProviderManager;
    private static IdentityVerificationManager identityVerificationManager;

    private DaonAuthenticatorDataHolder() {
    }

    public static IdVProviderManager getIdVProviderManager() {

        if (idVProviderManager == null) {
            throw new RuntimeException("IdVProviderManager was not set during " +
                    "DaonAuthenticatorServiceComponent startup");
        }
        return idVProviderManager;
    }

    public static void setIdVProviderManager(IdVProviderManager idVProviderManager) {

        DaonAuthenticatorDataHolder.idVProviderManager = idVProviderManager;
    }

    public static IdentityVerificationManager getIdentityVerificationManager() {

        if (identityVerificationManager == null) {
            throw new RuntimeException("IdentityVerificationManager was not set during " +
                    "DaonAuthenticatorServiceComponent startup");
        }
        return identityVerificationManager;
    }

    public static void setIdentityVerificationManager(IdentityVerificationManager identityVerificationManager) {

        DaonAuthenticatorDataHolder.identityVerificationManager = identityVerificationManager;
    }
}
