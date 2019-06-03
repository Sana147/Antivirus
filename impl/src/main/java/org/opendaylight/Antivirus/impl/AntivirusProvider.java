/*
 * Copyright © 2017 Sana and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.Antivirus.impl;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.sal.binding.api.BindingAwareBroker.RpcRegistration;
import org.opendaylight.controller.sal.binding.api.RpcProviderRegistry;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.antivirus.rev150105.AntivirusService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AntivirusProvider {

    private static final Logger LOG = LoggerFactory.getLogger(AntivirusProvider.class);

    private final DataBroker dataBroker;
    private RpcRegistration<AntivirusService> serviceRegistration;
	private RpcProviderRegistry rpcProviderRegistry;

    public AntivirusProvider(final DataBroker dataBroker, RpcProviderRegistry rpcProviderRegistry) {
        this.dataBroker = dataBroker;
        this.rpcProviderRegistry = rpcProviderRegistry;
    }

    /**
     * Method called when the blueprint container is created.
     */
    public void init() {
        LOG.info("AntivirusProvider Session Initiated");
        serviceRegistration = rpcProviderRegistry.addRpcImplementation(AntivirusService.class, new AntivirusImpl(dataBroker));
    }

    /**
     * Method called when the blueprint container is destroyed.
     */
    public void close() {
        LOG.info("AntivirusProvider Closed");
        serviceRegistration.close();
    }
}