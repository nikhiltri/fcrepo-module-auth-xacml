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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.fcrepo.auth.common.FedoraAuthorizationDelegate;
import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.fcrepo.http.commons.session.SessionFactory;
import org.fcrepo.kernel.exception.RepositoryRuntimeException;
import org.jboss.security.xacml.sunxacml.BasicEvaluationCtx;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.PDP;
import org.jboss.security.xacml.sunxacml.PDPConfig;
import org.jboss.security.xacml.sunxacml.ParsingException;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Result;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinder;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.ResourceFinder;
import org.jboss.security.xacml.sunxacml.finder.impl.CurrentEnvModule;
import org.modeshape.jcr.value.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * Responsible for resolving Fedora's permissions within ModeShape via a XACML
 * Policy Decision Point (PDP).
 * @author Gregory Jansen
 */
@Component("fad")
public class XACMLAuthorizationDelegate implements FedoraAuthorizationDelegate,
        ApplicationContextAware {

    /**
     * Class-level logger.
     */
    private static final Logger LOGGER = LoggerFactory
            .getLogger(XACMLAuthorizationDelegate.class);

    /**
     * The name of Fedora's subject finder module bean. (prototype)
     */
    private static final String SUBJECT_ATTRIBUTE_FINDER_BEAN =
            "subjectAttributeFinderModule";

    /**
     * The name of Fedora's environment finder module bean. (prototype)
     */
    private static final String ENVIRONMENT_ATTRIBUTE_FINDER_BEAN =
            "environmentAttributeFinderModule";

    /**
     * The XACML PDP.
     */
    private PDP pdp = null;

    /**
     * The standard environment attribute finder, supplies date/time.
     */
    private CurrentEnvModule currentEnvironmentAttributeModule =
            new CurrentEnvModule();

    /**
     * The Fedora policy finder module.
     */
    @Autowired
    private FedoraPolicyFinderModule fedoraPolicyFinderModule;

    /**
     * The Fedora resource finder module.
     */
    @Autowired
    private FedoraResourceFinderModule fedoraResourceFinderModule;

    /**
     * The triple-based resource attribute finder module.
     */
    @Autowired
    private TripleAttributeFinderModule tripleResourceAttributeFinderModule;

    /**
     * The SPARQL-based resource attribute finder module.
     */
    @Autowired
    private SparqlResourceAttributeFinderModule
    sparqlResourceAttributeFinderModule;

    /**
     * The Spring application context.
     */
    private ApplicationContext applicationContext;

    /**
     * The provider for access roles.
     */
    @Autowired
    private AccessRolesProvider accessRolesProvider;

    /**
     * Fedora's ModeShape session factory.
     */
    @Autowired
    private SessionFactory sessionFactory;

    /**
     * Configures the Sun XACML PDP for resource and policy finding.
     */
    @PostConstruct
    public final void init() {
        final PolicyFinder policyFinder = new PolicyFinder();
        policyFinder
                .setModules(Collections.singleton(fedoraPolicyFinderModule));
        final ResourceFinder resourceFinder = new ResourceFinder();
        resourceFinder.setModules(Collections
                .singletonList(fedoraResourceFinderModule));
        final PDPConfig pdpConfig =
                new PDPConfig(new AttributeFinder(), policyFinder,
                        resourceFinder);
        pdp = new PDP(pdpConfig);
        LOGGER.info("XACML Policy Decision Point (PDP) initialized");
    }

    /*
     * The application context is used to create beans from prototypes.
     * (non-Javadoc)
     * @see
     * org.springframework.context.ApplicationContextAware#setApplicationContext
     * (org.springframework.context.ApplicationContext)
     */
    @Override
    public final void
    setApplicationContext(final ApplicationContext appContext) {
        this.applicationContext = appContext;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.common.FedoraAuthorizationDelegate#hasPermission(javax
     * .jcr.Session, org.modeshape.jcr.value.Path, java.lang.String[])
     */
    @Override
    public final boolean hasPermission(final Session session,
            final Path absPath,
            final String[] actions) {
        EvaluationCtx evaluationCtx = null;
        final AttributeFinder myAttributeFinder = buildAttributeFinder(session);
        final Set<String> roles = getRoles(session, absPath);

        final RequestCtx request =
                getRequestContext(session, absPath, actions, roles);

        try {
            evaluationCtx =
                    new BasicEvaluationCtx(request, myAttributeFinder, true);
        } catch (final ParsingException e) {
            throw new Error(e);
        }
        final ResponseCtx resp = pdp.evaluate(evaluationCtx);
        for (final Object o : resp.getResults()) {
            final Result res = (Result) o;
            if (Result.DECISION_PERMIT != res.getDecision()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Builds a XACML request from ModeShape parameters and Fedora roles.
     * @param session the ModeShape session
     * @param absPath the path to the resource node
     * @param actions the actions requested
     * @param roles the effective roles for this session/path
     * @return a XACML request context
     */
    private RequestCtx
    getRequestContext(final Session session, final Path absPath,
                    final String[] actions, final Set<String> roles) {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * @param session modeshape session
     * @param absPath node path
     * @return effective content roles for session
     */
    private Set<String> getRoles(final Session session, final Path absPath) {
        Set<String> result = null;

        @SuppressWarnings("unchecked")
        Set<Principal> allPrincipals =
                (Set<Principal>) session.getAttribute(FEDORA_ALL_PRINCIPALS);
        if (allPrincipals == null) {
            allPrincipals = Collections.emptySet();
        }

        try {
            final Session internalSession = sessionFactory.getInternalSession();
            final Map<String, List<String>> acl =
                    accessRolesProvider.findRolesForPath(absPath,
                            internalSession);
            result = resolveUserRoles(acl, allPrincipals);
            LOGGER.debug("roles for this request: {}", result);
        } catch (final RepositoryException e) {
            throw new RepositoryRuntimeException(
                    "Cannot look up node information on " + absPath
                    + " for permissions check.", e);
        }
        return result;
    }

    /**
     * Builds a global attribute finder from injected modules that may use
     * current session information.
     *
     * @param session the modeshape session
     * @return an attribute finder
     */
    private AttributeFinder buildAttributeFinder(final Session session) {
        AttributeFinder result = null;
        // Custom finder per request will allow injection of Session
        final List<AttributeFinderModule> attributeFinderModules =
                new ArrayList<AttributeFinderModule>();
        attributeFinderModules.add(currentEnvironmentAttributeModule);
        attributeFinderModules.add(sparqlResourceAttributeFinderModule);

        // A subject attribute finder prototype is injected with Session
        if (applicationContext
                .containsBeanDefinition(SUBJECT_ATTRIBUTE_FINDER_BEAN)) {
            final AttributeFinderModule subjectAttributeFinder =
                    (AttributeFinderModule) applicationContext.getBean(
                            SUBJECT_ATTRIBUTE_FINDER_BEAN, session);
            attributeFinderModules.add(subjectAttributeFinder);
        }
        // An additional environment attribute finder prototype is injected with
        // Session
        if (applicationContext
                .containsBeanDefinition(ENVIRONMENT_ATTRIBUTE_FINDER_BEAN)) {
            final AttributeFinderModule environmentAttributeFinder =
                    (AttributeFinderModule) applicationContext.getBean(
                            ENVIRONMENT_ATTRIBUTE_FINDER_BEAN, session);
            attributeFinderModules.add(environmentAttributeFinder);
        }

        // the triple finder will have to look in modeshape for any valid
        // predicate URI, therefore it falls last in this list.
        attributeFinderModules.add(tripleResourceAttributeFinderModule);
        result = new AttributeFinder();
        result.setModules(attributeFinderModules);
        return result;
    }

    /**
     * Gathers effective roles.
     *
     * @param acl effective assignments for path
     * @param principals effective principals
     * @return set of effective content roles
     */
    public static Set<String>
    resolveUserRoles(final Map<String, List<String>> acl,
                    final Set<Principal> principals) {
        final Set<String> roles = new HashSet<>();
        for (final Principal p : principals) {
            final List<String> matchedRoles = acl.get(p.getName());
            if (matchedRoles != null) {
                LOGGER.debug("request principal matched role assignment: {}", p
                        .getName());
                roles.addAll(matchedRoles);
            }
        }
        return roles;
    }

}
