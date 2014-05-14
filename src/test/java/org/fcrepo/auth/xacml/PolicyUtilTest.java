package org.fcrepo.auth.xacml;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


/**
 * @author Gregory Jansen
 *
 */
public class PolicyUtilTest {

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void test() throws Exception {
        final String id =
                PolicyUtil.getID(FileUtils.openInputStream(
                new File("src/main/resources/policies/GlobalRolesPolicySet.xml")));
        Assert.assertEquals("info:fedora/policies/GlobalRolesPolicySet", id);

        final String path = PolicyUtil.getPathForId(id);
        Assert.assertEquals("/policies/GlobalRolesPolicySet", path);
    }

}
