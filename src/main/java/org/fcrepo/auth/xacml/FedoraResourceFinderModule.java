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

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinderModule;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinderResult;
import org.springframework.stereotype.Component;


/**
 * Locates resources that are subordinate to a Fedora resource.
 * @author Gregory Jansen
 */
@Component("fedoraResourceFinderModule")
public class FedoraResourceFinderModule extends ResourceFinderModule {

    /*
     * Does find child resources.
     * @see org.jboss.security.xacml.sunxacml.finder.ResourceFinderModule#
     * isChildSupported()
     */
    @Override
    public final boolean isChildSupported() {
        return true;
    }

    /*
     * Does find descendant resources.
     * @see org.jboss.security.xacml.sunxacml.finder.ResourceFinderModule#
     * isDescendantSupported()
     */
    @Override
    public final boolean isDescendantSupported() {
        return true;
    }

    /*
     * Finds ModeShape child resources based on parent ID and evaluation
     * context.
     * @see org.jboss.security.xacml.sunxacml.finder.ResourceFinderModule#
     * findChildResources(org.jboss.security.xacml.sunxacml.attr.AttributeValue,
     * org.jboss.security.xacml.sunxacml.EvaluationCtx)
     */
    @Override
    public final ResourceFinderResult findChildResources(
            final AttributeValue parentResourceId,
            final EvaluationCtx context) {
        // TODO Auto-generated method stub
        return super.findChildResources(parentResourceId, context);
    }

    /*
     * Finds ModeShape descendant resources based on parent ID and evaluation
     * context.
     * @see org.jboss.security.xacml.sunxacml.finder.ResourceFinderModule#
     * findDescendantResources
     * (org.jboss.security.xacml.sunxacml.attr.AttributeValue,
     * org.jboss.security.xacml.sunxacml.EvaluationCtx)
     */
    @Override
    public final ResourceFinderResult findDescendantResources(
            final AttributeValue parentResourceId,
            final EvaluationCtx context) {
        // TODO Auto-generated method stub
        return super.findDescendantResources(parentResourceId, context);
    }

}
