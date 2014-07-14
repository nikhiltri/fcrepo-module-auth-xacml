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


import static org.fcrepo.kernel.utils.TestHelpers.setField;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

import org.jboss.security.xacml.sunxacml.PDP;
import org.junit.Before;
import org.junit.Test;

/**
 * Created by mohideen on 7/11/14.
 */
public class PDPFactoryTest {

    private PDPFactory pdpFactory;

    @Before
    public void setUp() {
        pdpFactory = new PDPFactory();
        FedoraPolicyFinderModule fedoraPolicyFinderModule = new FedoraPolicyFinderModule();
        FedoraResourceFinderModule fedoraResourceFinderModule = new FedoraResourceFinderModule();
        setField(pdpFactory, "fedoraPolicyFinderModule", fedoraPolicyFinderModule);
        setField(pdpFactory, "fedoraResourceFinderModule", fedoraResourceFinderModule);
    }

    @Test
    public void testMakePdp() {
        assertThat(pdpFactory.makePDP(), instanceOf(PDP.class));
    }

}
