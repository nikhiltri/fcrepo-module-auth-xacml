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

import static org.fcrepo.auth.xacml.URIConstants.POLICY_URI_PREFIX;
import static org.fcrepo.auth.xacml.URIConstants.XACML_POLICY_PROPERTY;
import static org.slf4j.LoggerFactory.getLogger;

import java.net.URI;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.fcrepo.http.commons.session.SessionFactory;
import org.fcrepo.kernel.Datastream;
import org.fcrepo.kernel.services.DatastreamService;
import org.fcrepo.kernel.services.NodeService;
import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.MatchResult;
import org.jboss.security.xacml.sunxacml.Policy;
import org.jboss.security.xacml.sunxacml.PolicyMetaData;
import org.jboss.security.xacml.sunxacml.PolicySet;
import org.jboss.security.xacml.sunxacml.VersionConstraints;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderResult;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 * Locates a policy in ModeShape by evaluation context or by URI.
 * 
 * @author Gregory Jansen
 * @author bbpennel
 */
@Component("fedoraPolicyFinderModule")
public class FedoraPolicyFinderModule extends PolicyFinderModule {

    private static final Logger LOGGER = getLogger(FedoraPolicyFinderModule.class);

    @Autowired
    private SessionFactory sessionFactory;

    @Autowired
    private DatastreamService datastreamService;

    @Autowired
    private NodeService nodeService;

    private PolicyFinder finder;

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

    /**
     * Retrieves the policy from the given policy node
     *
     * @param policyNode
     * @return
     */
    private AbstractPolicy getPolicy(final Datastream policyDatastream) {
        return loadPolicy(policyDatastream);
    }

    /**
     * Creates a new policy or policy set object from the given policy node
     * 
     * @param policyNode
     * @return
     */
    private AbstractPolicy loadPolicy(final Datastream policyDatastream) {
        try {
            // create the factory
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setIgnoringComments(true);

            DocumentBuilder db = null;
            factory.setNamespaceAware(true);
            factory.setValidating(false);
            db = factory.newDocumentBuilder();

            // Parse the policy content
            final Document doc = db.parse(policyDatastream.getContent());

            // handle the policy, if it's a known type
            final Element root = doc.getDocumentElement();
            final String name = root.getTagName();

            if (name.equals("Policy")) {
                return Policy.getInstance(root);
            } else if (name.equals("PolicySet")) {
                return PolicySet.getInstance(root, finder);
            } else {
                // this isn't a root type that we know how to handle
                throw new Exception("Unknown root document type: " + name);
            }
        } catch (final Exception e) {
            LOGGER.error("Unable to parse policy from {}", e, policyDatastream);
        }

        // a default fall-through in the case of an error
        return null;
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

        final String path = context.getResourceId().getValue().toString();

        Node nodeWithPolicy;
        try {
            final Session internalSession = sessionFactory.getInternalSession();
            final Node node = internalSession.getNode(path);

            // Verify that the node is part of the repository hierarchy
            if (node.getParent() == null) {
                return new PolicyFinderResult();
            }

            // Walk up the hierarchy to find the first node with a policy
            // assigned
            nodeWithPolicy = node;
            while (nodeWithPolicy != null && !nodeWithPolicy.hasProperty(XACML_POLICY_PROPERTY)) {
                nodeWithPolicy = nodeWithPolicy.getParent();
            }

            final Datastream policyDatastream =
                    datastreamService.asDatastream(nodeWithPolicy.getProperty(XACML_POLICY_PROPERTY).getNode());

            if (policyDatastream == null) {
                return new PolicyFinderResult();
            }

            final AbstractPolicy policy = getPolicy(policyDatastream);

            // Evaluate if the policy targets match the current context
            final MatchResult match = policy.match(context);
            final int result = match.getResult();

            if (result == MatchResult.INDETERMINATE) {
                return new PolicyFinderResult(match.getStatus());
            }

            // Found a good policy, return it
            if (result == MatchResult.MATCH) {
                return new PolicyFinderResult(policy);
            }

            return new PolicyFinderResult();
        } catch (final RepositoryException e) {
            LOGGER.warn("Failed to retrieve a policy for {}", e, path);
            return new PolicyFinderResult();
        }
    }

    /*
     * Find a policy in ModeShape by reference URI.
     * @see
     * org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule#findPolicy
     * (java.net.URI, int, org.jboss.security.xacml.sunxacml.VersionConstraints,
     * org.jboss.security.xacml.sunxacml.PolicyMetaData)
     */
    @Override
    public final PolicyFinderResult findPolicy(final URI idReference, final int type,
            final VersionConstraints constraints, final PolicyMetaData parentMetaData) {

        try {
            String path = idReference.toString();
            if (!path.startsWith(POLICY_URI_PREFIX)) {
                LOGGER.warn("Policy reference must begin with fcrepo, but was {}", path);
                return new PolicyFinderResult();
            }
            path = "/" + path.substring(POLICY_URI_PREFIX.length());

            final Session internalSession = sessionFactory.getInternalSession();
            final Datastream policyDatastream =
                    datastreamService.getDatastream(internalSession, idReference.toString());

            final AbstractPolicy policy = getPolicy(policyDatastream);

            return new PolicyFinderResult(policy);
        } catch (final RepositoryException e) {
            LOGGER.warn("Failed to retrieve a policy for {}", e, idReference.toString());
            return new PolicyFinderResult();
        }
    }

    /*
     * (non-Javadoc)
     * @see
     * org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule#init(org.
     * jboss.security.xacml.sunxacml.finder.PolicyFinder)
     */
    @Override
    public void init(final PolicyFinder finder) {
        this.finder = finder;

    }

}
