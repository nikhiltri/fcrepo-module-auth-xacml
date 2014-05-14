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

package org.fcrepo.integration.auth.xacml;

import static javax.ws.rs.core.Response.Status.NO_CONTENT;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.text.MessageFormat;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.entity.BasicHttpEntity;
import org.fcrepo.auth.roles.basic.integration.BasicRolesAdminIT;
import org.fcrepo.auth.roles.common.integration.RolesFadTestObjectBean;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hp.hpl.jena.util.FileUtils;

/**
 * This test reuses the existing basic admin roles test, adding the XACML PDP and policies.
 *
 * @author Gregory Jansen
 */
public class BasicAdminRoleXACMLIT extends BasicRolesAdminIT {

    private boolean policiesLoaded = false;

    /**
     * Class logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(BasicAdminRoleXACMLIT.class);

    private final RolesFadTestObjectBean policies = new RolesFadTestObjectBean();

    private void addPolicy(final String path) throws Exception {
        final String xacml = FileUtils.readWholeFileAsUTF8(path);
        String name = new File(path).getName();
        name = name.substring(0, name.length() - 5);
        policies.addDatastream(name, xacml);
    }

    protected void unlinkPolicies(final String objectPath) throws Exception {
        final String subjectURI = serverAddress + objectPath;
        final HttpPatch patch = new HttpPatch(subjectURI);
        // setAuth(patch, "fedoraAdmin");
        patch.addHeader("Content-Type", "application/sparql-update");
        final BasicHttpEntity e = new BasicHttpEntity();
        e.setContent(new ByteArrayInputStream(
                ("DELETE { <" + subjectURI + "> <http://fedora.info/definitions/v4/authorization#policy> ?o } " +
                        "WHERE { <" + subjectURI + "> <http://fedora.info/definitions/v4/authorization#policy> ?o }")
                        .getBytes()));
        patch.setEntity(e);
        LOGGER.debug("PATCH: {}", patch.getURI());
        final HttpResponse response = client.execute(patch);
        assertEquals(NO_CONTENT.getStatusCode(), response.getStatusLine().getStatusCode());
    }

    protected void linkPolicy(final String objectPath, final String policyPath) throws Exception {
        final String subjectURI = serverAddress + objectPath;
        final String policyURI = policyPath;
        final HttpPatch patch = new HttpPatch(subjectURI);
        // setAuth(patch, "fedoraAdmin");
        patch.addHeader("Content-Type", "application/sparql-update");
        final BasicHttpEntity e = new BasicHttpEntity();
        final StringBuilder sb = new StringBuilder();
        sb.append("INSERT { ")
            .append(MessageFormat.format(
                    "<{0}> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://fedora.info/definitions/v4/authorization#xacmlAssignable> . ",
                    subjectURI))
            .append(MessageFormat.format(
                    "<{0}> <http://fedora.info/definitions/v4/authorization#policy> <{1}> . ",
                    subjectURI, policyURI))
            .append("} WHERE { }");
        e.setContent(new ByteArrayInputStream(sb.toString().getBytes()));
        patch.setEntity(e);
        LOGGER.debug("PATCH: {}", patch.getURI());
        final HttpResponse response = client.execute(patch);
        assertEquals(NO_CONTENT.getStatusCode(), response.getStatusLine().getStatusCode());
    }

    /**
     * This test is good for running individually to find bootstrap problems with the delegate. All it does is build the
     * Fedora XACML environment.
     */
    @Test
    public void test() {
        // in you want to run a quick test of bootstrap
    }

}
