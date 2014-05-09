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

import static org.fcrepo.auth.xacml.URIConstants.ATTRIBUTEID_ACTION_ID;
import static org.fcrepo.auth.xacml.URIConstants.ATTRIBUTEID_RESOURCE_ID;
import static org.fcrepo.auth.xacml.URIConstants.ATTRIBUTEID_RESOURCE_SCOPE;
import static org.fcrepo.auth.xacml.URIConstants.ATTRIBUTEID_RESOURCE_WORKSPACE;
import static org.fcrepo.auth.xacml.URIConstants.ATTRIBUTEID_SUBJECT_ID;

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
import org.jboss.security.xacml.sunxacml.ParsingException;
import org.jboss.security.xacml.sunxacml.attr.StringAttribute;
import org.jboss.security.xacml.sunxacml.ctx.Attribute;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Result;
import org.jboss.security.xacml.sunxacml.ctx.Subject;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinder;
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

    /**
     * Configures the Sun XACML PDP for resource and policy finding.
     */
    @PostConstruct
    public final void init() {

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
     * Builds a XACML request from ModeShape parameters and Fedora roles.
     *
     * @param session the ModeShape session
     * @param absPath the path to the resource node
     * @param actions the actions requested
     * @param roles the effective roles for this session/path
     * @param subjectAttributeFinder
     * @return a XACML request context
     */
    private RequestCtx getRequestContext(final Session session,
            final Path absPath, final String[] actions,
            final Set<String> roles) {
        final List<Subject> subjectList =
                Collections.singletonList(getSubject(session, roles));
        final List<Attribute> resourceList =
                getResourceAttributes(session, absPath);
        final List<Attribute> actionList = new ArrayList<Attribute>();
        for (final String action : actions) {
            final Attribute a =
                    new Attribute(ATTRIBUTEID_ACTION_ID,
                            null, null, new StringAttribute(action));
            actionList.add(a);
            if ("remove".equals(action)) {
                final Attribute scope =
                        new Attribute(ATTRIBUTEID_RESOURCE_SCOPE, null, null,
                                new StringAttribute("Descendants"));
                resourceList.add(scope);
            }
        }
        final List<Attribute> environmentList = Collections.emptyList();
        return new RequestCtx(subjectList, resourceList, actionList,
                environmentList);
    }

    /**
     * Adds resource attributes to the request.
     *
     * @param session the ModeShape session
     * @param absPath the path to the node or propery
     * @return a list of resource attributes
     */
    private List<Attribute> getResourceAttributes(final Session session,
            final Path absPath) {
        final List<Attribute> result = new ArrayList<Attribute>();
        // resource id
        final Attribute rid =
                new Attribute(ATTRIBUTEID_RESOURCE_ID, null,
                        null, new StringAttribute(absPath.getString()));
        result.add(rid);
        // workspace id
        final Attribute wid =
                new Attribute(ATTRIBUTEID_RESOURCE_WORKSPACE, null, null,
                        new StringAttribute(
                        session.getWorkspace().getName()));
        result.add(wid);
        return result;
    }

    /**
     * Builds the XACML request subject.
     *
     * @param session ModeShape session
     * @param roles Fedora roles
     * @return a populated XACML Subject
     */
    private Subject getSubject(final Session session, final Set<String> roles) {
        // build subject
        final List<Attribute> subjectAttrs = new ArrayList<Attribute>();

        {
            // user principal => subject-id
            final Principal user =
                    (Principal) session.getAttribute(FEDORA_USER_PRINCIPAL);
            final StringAttribute v = new StringAttribute(user.getName());
            final Attribute sid =
                    new Attribute(ATTRIBUTEID_SUBJECT_ID,
                            null, null, v);
            subjectAttrs.add(sid);
        }

        // roles => role
        return new Subject(subjectAttrs);
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
        EvaluationCtx result = null;
        AttributeFinder myAttributeFinder = null;
        final List<AttributeFinderModule> attributeFinderModules =
                new ArrayList<AttributeFinderModule>();
        attributeFinderModules.add(currentEnvironmentAttributeModule);
        attributeFinderModules.add(sparqlResourceAttributeFinderModule);

        // A subject attribute finder prototype is injected with Session
        AttributeFinderModule subjectAttributeFinder = null;
        if (applicationContext
                .containsBeanDefinition(SUBJECT_ATTRIBUTE_FINDER_BEAN)) {
            subjectAttributeFinder =
                    (AttributeFinderModule) applicationContext.getBean(
                            SUBJECT_ATTRIBUTE_FINDER_BEAN, session);
            attributeFinderModules.add(subjectAttributeFinder);
        }

        // Additional environment attribute finder is injected with Session
        AttributeFinderModule environmentAttributeFinder = null;
        if (applicationContext
                .containsBeanDefinition(ENVIRONMENT_ATTRIBUTE_FINDER_BEAN)) {
            environmentAttributeFinder =
                    (AttributeFinderModule) applicationContext.getBean(
                            ENVIRONMENT_ATTRIBUTE_FINDER_BEAN, session);
            attributeFinderModules.add(environmentAttributeFinder);
        }

        // Triple attribute finder will look in modeshape for any valid
        // predicate URI, therefore it falls last in this list.
        attributeFinderModules.add(tripleResourceAttributeFinderModule);
        myAttributeFinder = new AttributeFinder();
        myAttributeFinder.setModules(attributeFinderModules);

        final Set<String> roles = getRoles(session, absPath);

        final RequestCtx request =
                getRequestContext(session, absPath, actions, roles);

        try {
            result = new BasicEvaluationCtx(request, myAttributeFinder, true);
        } catch (final ParsingException e) {
            throw new Error(e);
        }
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
