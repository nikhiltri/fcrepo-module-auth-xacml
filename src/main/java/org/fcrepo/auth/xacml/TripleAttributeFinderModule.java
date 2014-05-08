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
import java.util.Collections;
import java.util.Set;

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.AttributeDesignator;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;
import org.springframework.stereotype.Component;
import org.w3c.dom.Node;


/**
 * Finds resource attributes based on triples in the Fedora graph. Retrieves
 * values where the attribute URI matches the triple predicate and the triple
 * object can be supplied as the requested data type.
 *
 * @author Gregory Jansen
 */
@Component
public class TripleAttributeFinderModule extends AttributeFinderModule {

    /**
     * Supported designator types.
     */
    private static final Set<Integer> DESIGNATOR_TYPES = Collections
            .unmodifiableSet(Collections
                    .singleton(AttributeDesignator.RESOURCE_TARGET));

    /**
     * Supports designators.
     *
     * @see org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule#
     *      isDesignatorSupported()
     * @return if designator is supported.
     */
    @Override
    public final boolean isDesignatorSupported() {
        return true;
    }

    /**
     * Supports selectors.
     * @see org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule#
     *      isSelectorSupported()
     * @return if selector is supported
     */
    @Override
    public final boolean isSelectorSupported() {
        return true;
    }

    /**
     * Supports resource attributes.
     *
     * @see org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule#
     *      getSupportedDesignatorTypes()
     * @return the supported designator types.
     */
    @Override
    public final Set<Integer> getSupportedDesignatorTypes() {
        return TripleAttributeFinderModule.DESIGNATOR_TYPES;
    }

    /**
     * This finder will try to resolve resource attributes with any ID.
     * (non-Javadoc)
     *
     * @see org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule#
     *      getSupportedIds()
     * @return that any attribute ID is supported (null)
     */
    @Override
    public final Set<?> getSupportedIds() {
        return null;
    }

    /**
     * Finds the matching triples values.
     * @see
     * org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule#findAttribute
     * (java.net.URI, java.net.URI, java.net.URI, java.net.URI,
     * org.jboss.security.xacml.sunxacml.EvaluationCtx, int)
     */
    @Override
    public final EvaluationResult findAttribute(final URI attributeType,
            final URI attributeId, final URI issuer, final URI subjectCategory,
            final EvaluationCtx context, final int designatorType) {
        // TODO Auto-generated method stub
        return super.findAttribute(attributeType, attributeId, issuer,
                subjectCategory, context, designatorType);
    }

    /**
     * Finds the matching triple values.
     *
     * @see
     * org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule#findAttribute
     *      (java.lang.String, org.w3c.dom.Node, java.net.URI,
     *      org.jboss.security.xacml.sunxacml.EvaluationCtx, java.lang.String)
     * @return the attribute values
     */
    @Override
    public final EvaluationResult findAttribute(final String contextPath,
            final Node namespaceNode, final URI attributeType,
            final EvaluationCtx context, final String xpathVersion) {
        // TODO Auto-generated method stub
        return super.findAttribute(contextPath, namespaceNode, attributeType,
                context, xpathVersion);
    }

}
