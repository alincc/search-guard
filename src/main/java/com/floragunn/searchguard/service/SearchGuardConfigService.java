/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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
 * 
 */

package com.floragunn.searchguard.service;

import com.floragunn.searchguard.util.ConfigConstants;
import org.apache.commons.io.IOUtils;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.elasticsearch.action.count.CountRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.concurrent.FutureUtils;
import org.elasticsearch.indices.IndexMissingException;
import org.elasticsearch.indices.IndicesService;

import java.util.concurrent.*;

public class SearchGuardConfigService extends AbstractLifecycleComponent<SearchGuardConfigService> {

    private final Client client;
    private final Settings settings;
    private final String securityConfigurationIndex;
    private final IndicesService indicesService;
    private final CountDownLatch latch = new CountDownLatch(1);
    private volatile BytesReference securityConfiguration;
    private ScheduledThreadPoolExecutor scheduler;
    private ScheduledFuture scheduledFuture;

    @Inject
    public SearchGuardConfigService(final Settings settings, final Client client, final IndicesService indicesService) {
        super(settings);
        this.client = client;
        this.settings = settings;
        this.indicesService = indicesService;

        securityConfigurationIndex = settings.get(ConfigConstants.SEARCHGUARD_CONFIG_INDEX_NAME,
                ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX);

    }

    public String getSecurityConfigurationIndex() {
        return securityConfigurationIndex;
    }

    public BytesReference getSecurityConfiguration() {
        try {
            if (!latch.await(1, TimeUnit.MINUTES)) {
                throw new ElasticsearchException("Security configuration cannot be loaded for unknown reasons.");
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return securityConfiguration;
    }

    //blocking
    private void reloadConfig() throws Exception {
        createAclIfNoRecord();

        client.prepareGet(securityConfigurationIndex, "ac", "ac").setRefresh(true).execute(new ActionListener<GetResponse>() {

            @Override
            public void onResponse(final GetResponse response) {

                if (response.isExists() && !response.isSourceEmpty()) {
                    securityConfiguration = response.getSourceAsBytesRef();
                    latch.countDown();
                    logger.trace("Security configuration reloaded");
                }
            }

            @Override
            public void onFailure(final Throwable e) {
                if (e instanceof IndexMissingException) {
                    logger.debug(
                            "Try to refresh security configuration but it failed due to {} - This might be ok if security setup not complete yet.",
                            e.toString());
                } else {
                    logger.error("Try to refresh security configuration but it failed due to {}", e, e.toString());
                }
            }
        });
    }

    private void createAclIfNoRecord() throws Exception {
        logger.debug("Verifying ACL rules");

        if (!indexExists()) {
            createIndex();
        }

        if (defaultIndexIsEmpty()) {
            logger.info("Creating default ACL rules");

            // Load default ACL
            byte[] defaultAcl = IOUtils.toString(SearchGuardConfigService.class.getClassLoader().getResourceAsStream("default-acl.json")).getBytes();

            // Create index
            client.prepareIndex(securityConfigurationIndex, "ac", "ac")
                    .setSource(defaultAcl)
                    .execute()
                    .actionGet();

            logger.info("Default ACL rules created successfully.");
        }
    }

    private boolean defaultIndexIsEmpty() {
        CountRequest countRequest = new CountRequest(securityConfigurationIndex);
        return client.count(countRequest).actionGet().getCount() == 0;
    }

    private boolean createIndex() {
        CreateIndexRequest index = new CreateIndexRequest(securityConfigurationIndex);
        return client.admin().indices().create(index).actionGet().isAcknowledged();
    }

    private boolean indexExists() {
        IndicesExistsRequest index = new IndicesExistsRequest(securityConfigurationIndex);
        return client.admin().indices().exists(index).actionGet().isExists();
    }

    @Override
    protected void doStart() throws ElasticsearchException {
        this.scheduler = (ScheduledThreadPoolExecutor) Executors.newScheduledThreadPool(1,
                EsExecutors.daemonThreadFactory(client.settings(), "search_guard_config_service"));
        this.scheduler.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.scheduler.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
        this.scheduledFuture = this.scheduler.scheduleWithFixedDelay(new Reload(), 5, 1, TimeUnit.SECONDS);
    }

    @Override
    protected void doStop() throws ElasticsearchException {
        FutureUtils.cancel(this.scheduledFuture);
        this.scheduler.shutdown();

    }

    @Override
    protected void doClose() throws ElasticsearchException {
        FutureUtils.cancel(this.scheduledFuture);
        this.scheduler.shutdown();

    }

    private class Reload implements Runnable {
        @Override
        public void run() {
            synchronized (SearchGuardConfigService.this) {
                try {
                    reloadConfig();
                } catch (Exception e) {
                    logger.error("Failed to reload configuration", e);
                }
            }
        }
    }
}
