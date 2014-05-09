/**
 * Copyright 2014 DuraSpace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.fcrepo.auth.xacml;

import java.util.Collections;

import org.jboss.security.xacml.sunxacml.PDP;
import org.jboss.security.xacml.sunxacml.PDPConfig;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Factory that creates the XACML Policy Decision Point.
 *
 * @author Gregory Jansen
 */
public class PDPFactoryBean {

    /**
     * Creates the factory.
     */
    public PDPFactoryBean() {
    }

    /**
     * Class logger.
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(PDPFactoryBean.class);

    /**
     * Make a PDP for the Fedora environment.
     *
     * @see org.springframework.beans.factory.FactoryBean#getObject()
     * @param fedoraPolicyFinderModule policy finder module
     * @param fedoraResourceFinderModule resource finder module
     * @return the PDP
     */
    public final PDP makePDP(
            final FedoraPolicyFinderModule fedoraPolicyFinderModule,
            final FedoraResourceFinderModule fedoraResourceFinderModule) {
        final PolicyFinder policyFinder = new PolicyFinder();
        policyFinder
                .setModules(Collections.singleton(fedoraPolicyFinderModule));
        final ResourceFinder resourceFinder = new ResourceFinder();
        resourceFinder.setModules(Collections
                .singletonList(fedoraResourceFinderModule));
        final PDPConfig pdpConfig =
                new PDPConfig(new AttributeFinder(), policyFinder,
                        resourceFinder);
        final PDP pdp = new PDP(pdpConfig);
        LOGGER.info("XACML Policy Decision Point (PDP) initialized");
        return pdp;
    }

}
