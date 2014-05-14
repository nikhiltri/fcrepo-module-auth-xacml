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

import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.servlet.http.HttpServletRequest;

import org.fcrepo.auth.common.FedoraAuthorizationDelegate;
import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.fcrepo.http.commons.session.SessionFactory;
import org.fcrepo.kernel.exception.RepositoryRuntimeException;
import org.fcrepo.kernel.services.NodeService;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.PDP;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Result;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;
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
 *
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

    @Autowired
    private PDPFactory pdpFactory;

    /**
     * The XACML PDP.
     */
    private PDP pdp = null;

    /**
     * @return the pdp
     */
    public final PDP getPdp() {
        return pdp;
    }

    /**
     * @param pdp the pdp to set
     */
    public final void setPdp(final PDP pdp) {
        this.pdp = pdp;
    }

    /**
     * The standard environment attribute finder, supplies date/time.
     */
    private CurrentEnvModule currentEnvironmentAttributeModule =
            new CurrentEnvModule();

    /**
     * The triple-based resource attribute finder module.
     */
    @Autowired
    private TripleAttributeFinderModule tripleResourceAttributeFinderModule;

    /**
     * The SPARQL-based resource attribute finder module.
     */
    @Autowired
    private SparqlResourceAttributeFinderModule sparqlResourceAttributeFinderModule;

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

    @Autowired
    private NodeService nodeService;

    /**
     * Configures the delegate.
     *
     * @throws IOException
     * @throws RepositoryException
     */
    @PostConstruct
    public final void init() throws RepositoryException, IOException {
        pdp = pdpFactory.makePDP();
        if (pdp == null) {
            throw new Error("There is no PDP wired by the factory in the Spring context.");
        }
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
            final Path absPath, final String[] actions) {
        final EvaluationCtx evaluationCtx =
                buildEvaluationContext(session, absPath, actions);

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
                    "Cannot look up node information on " + absPath +
                            " for permissions check.", e);
        }
        return result;
    }

    /**
     * Builds a global attribute finder from injected modules that may use
     * current session information.
     *
     * @param session the ModeShape session
     * @param absPath the node or property path
     * @param actions the actions requested
     * @return an attribute finder
     */
    private EvaluationCtx buildEvaluationContext(final Session session,
            final Path absPath, final String[] actions) {
        final FedoraEvaluationCtxBuilder builder =
                new FedoraEvaluationCtxBuilder();
        builder.addFinderModule(currentEnvironmentAttributeModule);
        builder.addFinderModule(sparqlResourceAttributeFinderModule);

        // A subject attribute finder prototype is injected with Session
        AttributeFinderModule subjectAttributeFinder = null;
        if (applicationContext
                .containsBeanDefinition(SUBJECT_ATTRIBUTE_FINDER_BEAN)) {
            subjectAttributeFinder =
                    (AttributeFinderModule) applicationContext.getBean(
                            SUBJECT_ATTRIBUTE_FINDER_BEAN, session);
            builder.addFinderModule(subjectAttributeFinder);
        }

        // environment attribute finder is injected with Session
        AttributeFinderModule environmentAttributeFinder = null;
        if (applicationContext
                .containsBeanDefinition(ENVIRONMENT_ATTRIBUTE_FINDER_BEAN)) {
            environmentAttributeFinder =
                    (AttributeFinderModule) applicationContext.getBean(
                            ENVIRONMENT_ATTRIBUTE_FINDER_BEAN, session);
            builder.addFinderModule(environmentAttributeFinder);
        }

        // Triple attribute finder will look in modeshape for any valid
        // predicate URI, therefore it falls last in this list.
        builder.addFinderModule(tripleResourceAttributeFinderModule);

        final Set<String> roles = getRoles(session, absPath);
        LOGGER.info("effective roles: {}", roles);
        final Principal user =
                (Principal) session.getAttribute(FEDORA_USER_PRINCIPAL);
        builder.addSubject(user.getName(), roles);
        // try {
        // final FedoraResource res = nodeService.getObject(session, absPath.getString());
        // res.get
        builder.addResourceID(absPath.getString());
        // }
        builder.addWorkspace(session.getWorkspace().getName());
        builder.addActions(actions);

        // TODO builder.addRequestIP()
        final HttpServletRequest request = (HttpServletRequest) session.getAttribute(FEDORA_SERVLET_REQUEST);
        builder.addOriginalRequestIP(request.getRemoteAddr());
        final EvaluationCtx result = builder.build();
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
