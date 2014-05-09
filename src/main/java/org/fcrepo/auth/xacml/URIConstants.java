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

import org.jboss.security.xacml.interfaces.XACMLConstants;


/**
 * URIs that are used in this module.
 *
 * @author Gregory Jansen
 */
public abstract class URIConstants {

    /**
     * ID of the subject (user principal).
     */
    public static final URI ATTRIBUTEID_SUBJECT_ID = URI
            .create(XACMLConstants.ATTRIBUTEID_SUBJECT_ID);

    /**
     * ID of the action (ModeShape permission name).
     */
    public static final URI ATTRIBUTEID_ACTION_ID = URI
            .create(XACMLConstants.ATTRIBUTEID_ACTION_ID);

    /**
     * ID of the resource (ModeShape node/property path).
     */
    public static final URI ATTRIBUTEID_RESOURCE_ID = URI
            .create(XACMLConstants.ATTRIBUTEID_RESOURCE_ID);

    /**
     * ID of the ModeShape workspace for this resource.
     */
    public static final URI ATTRIBUTEID_RESOURCE_WORKSPACE = URI
            .create("urn:fedora:xacml:2.0:resource:resource-workspace");

    /**
     * Scope of the request (DESCENDANTS if "remove", IMMEDIATE otherwise).
     */
    public static final URI ATTRIBUTEID_RESOURCE_SCOPE = URI
            .create("urn:oasis:names:tc:xacml:1.0:resource:scope");

}
