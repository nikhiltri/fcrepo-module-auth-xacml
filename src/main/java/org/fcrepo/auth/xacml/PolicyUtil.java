package org.fcrepo.auth.xacml;

import java.io.InputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Gregory Jansen
 *
 */
public class PolicyUtil {

    /**
     * Extract a policy set or policy ID for the document.
     *
     * @param policyStream the policy input
     * @return an identifier
     */
    public static String getID(final InputStream policyStream) {
        try {
            // create the factory
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setIgnoringComments(true);

            DocumentBuilder db = null;
            factory.setNamespaceAware(true);
            factory.setValidating(false);
            db = factory.newDocumentBuilder();

            // Parse the policy content
            final Document doc = db.parse(policyStream);

            // handle the policy, if it's a known type
            final Element root = doc.getDocumentElement();
            final String name = root.getTagName();

            if (name.equals("Policy")) {
                return root.getAttribute("PolicyId");
            } else if (name.equals("PolicySet")) {
                return root.getAttribute("PolicySetId");
            } else {
                // this isn't a root type that we know how to handle
                throw new Error("Unknown root document type: " + name);
            }
        } catch (final Exception e) {
            throw new Error("Unable to parse policy", e);
        }
    }

    /**
     * Gets the repository path for a policy ID.
     * 
     * @param id the policy id
     * @return the repository path
     */
    public static String getPathForId(final String id) {
        return id.substring(URIConstants.POLICY_URI_PREFIX.length());
    }
}
