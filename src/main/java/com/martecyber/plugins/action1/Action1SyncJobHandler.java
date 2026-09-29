package com.martecyber.plugins.action1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.IngestFacade;
import com.martecyber.ares.imports.IngestResult;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.integrations.IntegrationFacade;
import com.martecyber.ares.integrations.IntegrationView;
import com.martecyber.ares.jobs.JobFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Does the actual work of an Action1 sync — endpoint inventory for asset sync, vulnerabilities/
 * CVEs for vuln sync. No MSSP/child-account credential resolution: an Action1 API credential
 * targets one configured {@code orgId} (see {@link Action1Client}), so credential resolution is a
 * direct passthrough.
 *
 * <p>A plain object, not a Spring bean — {@link Action1IntegrationActionHandler} (the plugin's
 * one actual Spring-managed class) constructs one directly. Runs {@link #syncAssets}/
 * {@link #syncVulns} via a plain {@code CompletableFuture.runAsync(...)} instead of the original
 * {@code @Async} + self-injection trick, which needs a Spring AOP proxy this plugin's hand-
 * constructed objects don't have.
 */
public class Action1SyncJobHandler {

    private static final Logger log = LoggerFactory.getLogger(Action1SyncJobHandler.class);
    private static final String SOURCE_TYPE = "action1";

    private final JobFacade jobFacade;
    private final IntegrationFacade integrationFacade;
    private final Action1Client action1Client;
    private final Action1AssetParser assetParser;
    private final Action1VulnParser vulnParser;
    private final IngestFacade ingestFacade;
    private final ObjectMapper objectMapper;

    public Action1SyncJobHandler(JobFacade jobFacade,
                                  IntegrationFacade integrationFacade,
                                  Action1Client action1Client,
                                  Action1AssetParser assetParser,
                                  Action1VulnParser vulnParser,
                                  IngestFacade ingestFacade,
                                  ObjectMapper objectMapper) {
        this.jobFacade = jobFacade;
        this.integrationFacade = integrationFacade;
        this.action1Client = action1Client;
        this.assetParser = assetParser;
        this.vulnParser = vulnParser;
        this.ingestFacade = ingestFacade;
        this.objectMapper = objectMapper;
    }

    // ── Asset sync ───────────────────────────────────────────────────────────

    public void syncAssets(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = integrationFacade.loadCredentials(integrationId);

            log.info("Action1 asset sync start job={} integration={} project={}", jobId, integrationId, projectId);
            setStatus(jobId, null, 10);

            var endpoints = action1Client.fetchEndpoints(integration.settings(), creds);
            log.info("Action1: {} endpoints fetched for job={}", endpoints.size(), jobId);
            setStatus(jobId, null, 60);

            ParseResult parsed = assetParser.parseAssets(endpoints);
            setStatus(jobId, null, 80);

            IngestResult result = ingestFacade.ingest(projectId, orgId, SOURCE_TYPE, parsed);
            setStatus(jobId, null, 95);

            updateLastSync(integrationId);
            completeJob(jobId, Map.of(
                "assetsCreated", result.assetsCreated(),
                "action1EndpointsFound", endpoints.size(),
                "warnings", result.warnings().size()
            ));
            log.info("Action1 asset sync done job={} found={} created={}",
                jobId, endpoints.size(), result.assetsCreated());

        } catch (Exception ex) {
            log.error("Action1 asset sync failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Vuln sync ────────────────────────────────────────────────────────────

    public void syncVulns(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = integrationFacade.loadCredentials(integrationId);

            log.info("Action1 vuln sync start job={} integration={} project={}", jobId, integrationId, projectId);
            setStatus(jobId, null, 10);

            var vulns = action1Client.fetchVulnerabilities(integration.settings(), creds);
            log.info("Action1: {} vulnerabilities fetched for job={}", vulns.size(), jobId);
            setStatus(jobId, null, 70);

            ParseResult parsed = vulnParser.parseDetections(vulns);
            setStatus(jobId, null, 85);

            IngestResult result = ingestFacade.ingest(projectId, orgId, SOURCE_TYPE, parsed);
            setStatus(jobId, null, 95);

            updateLastSync(integrationId);
            completeJob(jobId, Map.of(
                "detectionsCreated", result.detectionsCreated(),
                "detectionsUpdated", result.detectionsUpdated(),
                "assetsCreated", result.assetsCreated(),
                "action1VulnsFound", vulns.size(),
                "warnings", result.warnings().size()
            ));
            log.info("Action1 vuln sync done job={} created={} updated={} assets={}",
                jobId, result.detectionsCreated(), result.detectionsUpdated(), result.assetsCreated());

        } catch (Exception ex) {
            log.error("Action1 vuln sync failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void setStatus(Long jobId, String status, Integer progress) {
        try { jobFacade.update(jobId, status, progress, null, null); }
        catch (Exception e) { log.warn("job update failed: {}", e.getMessage()); }
    }

    private void completeJob(Long jobId, Map<String, Object> resultData) {
        try {
            String json = objectMapper.writeValueAsString(resultData);
            jobFacade.update(jobId, "completed", 100, json, null);
        } catch (Exception e) { log.warn("Could not complete job {}: {}", jobId, e.getMessage()); }
    }

    private void safeFailJob(Long jobId, String error) {
        try { jobFacade.update(jobId, "failed", null, null, error); }
        catch (Exception ignored) {}
    }

    private void updateLastSync(Long integrationId) {
        try {
            integrationFacade.recordSyncResult(integrationId, "success");
        } catch (Exception e) {
            log.warn("Could not update lastSyncAt for integration {}: {}", integrationId, e.getMessage());
        }
    }
}
