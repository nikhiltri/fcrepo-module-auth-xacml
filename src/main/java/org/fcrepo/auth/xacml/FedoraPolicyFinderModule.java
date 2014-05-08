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

import java.net.URI;

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.PolicyMetaData;
import org.jboss.security.xacml.sunxacml.VersionConstraints;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderResult;
import org.springframework.stereotype.Component;


/**
 * Locates a policy in ModeShape by evaluation context or by URI.
 * @author Gregory Jansen
 */
@Component
public class FedoraPolicyFinderModule extends PolicyFinderModule {

    /*
     * This policy finder can find by request context.
     * @see org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule#
     * isRequestSupported()
     */
    @Override
    public final boolean isRequestSupported() {
        return true;
    }

    /*
     * This policy finder can find by reference (URI)
     * @see org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule#
     * isIdReferenceSupported()
     */
    @Override
    public final boolean isIdReferenceSupported() {
        return true;
    }

    /*
     * Find a policy in ModeShape that is appropriate for the evaluation
     * context.
     * @see
     * org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule#findPolicy
     * (org.jboss.security.xacml.sunxacml.EvaluationCtx)
     */
    @Override
    public final PolicyFinderResult findPolicy(final EvaluationCtx context) {
        // TODO Auto-generated method stub
        return super.findPolicy(context);
    }

    /*
     * Find a policy in ModeShape by reference URI.
     * @see
     * org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule#findPolicy
     * (java.net.URI, int, org.jboss.security.xacml.sunxacml.VersionConstraints,
     * org.jboss.security.xacml.sunxacml.PolicyMetaData)
     */
    @Override
    public final PolicyFinderResult findPolicy(final URI idReference,
            final int type,
            final VersionConstraints constraints,
            final PolicyMetaData parentMetaData) {
        // TODO Auto-generated method stub
        return super.findPolicy(idReference, type, constraints, parentMetaData);
    }

    /*
     * (non-Javadoc)
     * @see
     * org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule#init(org.
     * jboss.security.xacml.sunxacml.finder.PolicyFinder)
     */
    @Override
    public void init(final PolicyFinder finder) {
        // TODO Auto-generated method stub

    }

}
