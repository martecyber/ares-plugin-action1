package com.martecyber.plugins.action1;

import com.martecyber.ares.integrations.tools.IntegrationClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Action1 API client — RMM/patch-management platform whose "Endpoint Inventory" and
 * "Vulnerabilities" modules cover asset and CVE sync respectively (patch deployment itself is
 * out of scope for this integration). Sourced from the official {@code Action1Corp/PSAction1}
 * PowerShell SDK on GitHub (action1.com's own doc pages 403 automated fetches) — verified against
 * SDK source, not a live tenant; the product owner can confirm/correct against their own account.
 *
 * Auth: OAuth2 client-credentials, {@code POST /oauth2/token} with a JSON body ({@code client_id}/
 * {@code client_secret}, generated in the Action1 console), returning a short-lived bearer token
 * — minted fresh per sync call below rather than cached, same choice as {@link QualysClient}'s
 * gateway JWT (a sync runs at most a few times a day, so the extra token mint is negligible next
 * to the pagination cost).
 *
 * Multi-org: one API credential can see several Action1 organizations ({@code GET /organizations}
 * lists them) — {@link Integration#getSettings()} carries the specific {@code orgId} to sync,
 * same "operator picks one id up front" choice {@link QualysClient}'s {@code platform} setting
 * makes, rather than building an org browser into the credentials form.
 *
 * Rate limiting: {@link #fetchVulnerabilities} makes one {@code .../endpoints} call per distinct
 * CVE (the list endpoint carries no per-asset linkage of its own — see that method's own doc),
 * which bursts a lot of requests back-to-back for an org with many CVEs and was tripping
 * Action1's rate limit in practice. Every HTTP call in this client now goes through {@link
 * #sendWithRetry}, which backs off and retries on a 429 (honoring the SDK-documented {@code
 * details.retry_after} field when present, else the same exponential backoff — base 2s, doubling
 * — the official PSAction1 SDK uses), and {@link #fetchVulnerabilities} additionally paces itself
 * with a small fixed delay between CVEs so it doesn't lean on retry-after-the-fact as the only
 * defense.
 */
public class Action1Client implements IntegrationClient {

    private static final Logger log = LoggerFactory.getLogger(Action1Client.class);

    private record RegionUrl(String base) {}

    private static final Map<String, RegionUrl> REGIONS = Map.of(
        "NorthAmerica", new RegionUrl("https://app.action1.com/api/3.0"),
        "NA-2",         new RegionUrl("https://app.na-2.action1.com/api/3.0"),
        "Europe",       new RegionUrl("https://app.eu.action1.com/api/3.0"),
        "Australia",    new RegionUrl("https://app.au.action1.com/api/3.0")
    );
    private static final String DEFAULT_REGION = "NorthAmerica";
    private static final int PAGE_LIMIT = 200; // SDK's documented max
    private static final int MAX_RATE_LIMIT_RETRIES = 6;
    private static final long BASE_BACKOFF_MS = 2000;
    /** Pacing delay between the per-CVE {@code .../endpoints} calls in {@link #fetchVulnerabilities}
     *  — spreads the burst out proactively instead of relying only on {@link #sendWithRetry}
     *  reacting to 429s after the fact. */
    private static final long VULN_ENDPOINT_CALL_PACING_MS = 200;

    private final HttpClient http;
    private final ObjectMapper objectMapper;

    public Action1Client(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    @Override
    public String supports() { return "action1"; }

    @Override
    public void testConnection(String settingsJson, Map<String, String> credentials) throws Exception {
        String orgId = orgId(settingsJson);
        String token = mintToken(settingsJson, credentials);
        HttpResponse<String> resp = sendWithRetry(
            get(regionBase(settingsJson) + "/endpoints/managed/" + urlEncode(orgId) + "?from=0&limit=1", token));
        log.info("Action1 probe → HTTP {} body[0-300]={}", resp.statusCode(), snippet(resp.body(), 300));
        if (resp.statusCode() != 200)
            throw new RuntimeException("Action1 auth failed: HTTP " + resp.statusCode() + " — " + snippet(resp.body(), 300));
    }

    // ── OAuth2 client-credentials ────────────────────────────────────────────

    public String mintToken(String settingsJson, Map<String, String> creds) throws Exception {
        String body = objectMapper.writeValueAsString(Map.of(
            "client_id", creds.getOrDefault("client_id", ""),
            "client_secret", creds.getOrDefault("client_secret", "")
        ));
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(regionBase(settingsJson) + "/oauth2/token"))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(20))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> resp = sendWithRetry(req);
        if (resp.statusCode() != 200)
            throw new RuntimeException("Action1 token request failed: HTTP " + resp.statusCode()
                + " — " + snippet(resp.body(), 300));
        String token = objectMapper.readTree(resp.body()).path("access_token").asText(null);
        if (token == null || token.isBlank()) throw new RuntimeException("Action1 token response had no access_token");
        return token;
    }

    // ── Endpoints (assets): GET /endpoints/managed/{orgId} ──────────────────────

    public List<JsonNode> fetchEndpoints(String settingsJson, Map<String, String> creds) throws Exception {
        String token = mintToken(settingsJson, creds);
        String orgId = orgId(settingsJson);
        List<JsonNode> items = fetchAllPages(regionBase(settingsJson) + "/endpoints/managed/" + urlEncode(orgId), token);
        log.info("Action1: {} managed endpoint(s) fetched", items.size());
        return items;
    }

    // ── Vulnerabilities: GET /vulnerabilities/{orgId} + per-CVE endpoint linkage ────

    /** One CVE row from the list endpoint, plus the endpoint ids Action1 reports it affects
     *  (resolved via a second call per distinct CVE — the list endpoint carries no per-asset
     *  linkage of its own, see class javadoc). */
    public record VulnWithEndpoints(JsonNode vuln, List<String> endpointIds) {}

    public List<VulnWithEndpoints> fetchVulnerabilities(String settingsJson, Map<String, String> creds) throws Exception {
        String token = mintToken(settingsJson, creds);
        String orgId = orgId(settingsJson);
        List<JsonNode> vulns = fetchAllPages(regionBase(settingsJson) + "/vulnerabilities/" + urlEncode(orgId), token);
        log.info("Action1: {} vulnerabilit(y/ies) fetched, resolving affected endpoints per CVE", vulns.size());

        List<VulnWithEndpoints> out = new ArrayList<>();
        boolean first = true;
        boolean diagnosedOnce = false;
        for (JsonNode vuln : vulns) {
            String cveId = vuln.path("cve_id").asText(null);
            if (cveId == null || cveId.isBlank()) continue;
            if (!first) Thread.sleep(VULN_ENDPOINT_CALL_PACING_MS);
            first = false;
            String endpointsUrl = regionBase(settingsJson) + "/vulnerabilities/" + urlEncode(orgId) + "/" + urlEncode(cveId) + "/endpoints";

            // One-off raw dump of the very first call, independent of how fetchAllPages/endpointId
            // below parse it — captures ground truth even if the bug turns out to be the response
            // envelope's array key, not just the per-item id field (see class javadoc: this call's
            // shape was never verified against a live tenant). Look for this WARN line to fix
            // endpointId()/fetchAllPages's "items" key if the symptom is "CVEs fetched, 0 detections".
            if (!diagnosedOnce) {
                diagnosedOnce = true;
                try {
                    HttpResponse<String> raw = sendWithRetry(get(endpointsUrl, token));
                    log.warn("Action1 DIAGNOSTIC — raw response for {}: HTTP {} body[0-1500]={}",
                        endpointsUrl, raw.statusCode(), snippet(raw.body(), 1500));
                } catch (Exception e) {
                    log.warn("Action1 DIAGNOSTIC — raw call to {} failed: {}", endpointsUrl, e.getMessage());
                }
            }

            List<JsonNode> endpoints = fetchAllPages(endpointsUrl, token);
            List<String> endpointIds = endpoints.stream()
                .map(Action1Client::endpointId)
                .filter(id -> id != null && !id.isBlank())
                .toList();
            if (!endpoints.isEmpty() && endpointIds.isEmpty()) {
                log.warn("Action1: CVE {} — endpoints call returned {} item(s) but none yielded a usable id; "
                        + "first item raw: {}", cveId, endpoints.size(), snippet(endpoints.get(0).toString(), 500));
            }
            out.add(new VulnWithEndpoints(vuln, endpointIds));
        }
        return out;
    }

    // ── Pagination: from/limit + total_items, falling back to next_page ────────

    /** Mirrors the official SDK's own dual strategy: prefer advancing {@code from} until it
     *  reaches {@code total_items}, but fall back to following {@code next_page} when
     *  {@code total_items} is absent — the SDK does this defensively because not every Action1
     *  endpoint returns {@code total_items} reliably. */
    private List<JsonNode> fetchAllPages(String baseUrl, String token) throws Exception {
        List<JsonNode> out = new ArrayList<>();
        int from = 0;
        String nextPageUrl = null;
        int guard = 0;
        while (guard++ < 1000) {
            String url = nextPageUrl != null ? nextPageUrl
                : baseUrl + (baseUrl.contains("?") ? "&" : "?") + "from=" + from + "&limit=" + PAGE_LIMIT;
            HttpResponse<String> resp = sendWithRetry(get(url, token));
            if (resp.statusCode() != 200)
                throw new RuntimeException("Action1 request failed: HTTP " + resp.statusCode()
                    + " — " + snippet(resp.body(), 300) + " (url=" + url + ")");
            JsonNode root = objectMapper.readTree(resp.body());
            JsonNode items = root.path("items");
            int pageSize = 0;
            for (JsonNode item : items) { out.add(item); pageSize++; }
            if (pageSize == 0) break;

            JsonNode totalItemsNode = root.path("total_items");
            String next = root.path("next_page").asText(null);
            if (totalItemsNode.isIntegralNumber()) {
                from += pageSize;
                if (from >= totalItemsNode.asLong()) break;
                nextPageUrl = null;
            } else if (next != null && !next.isBlank()) {
                nextPageUrl = next;
            } else {
                break; // neither total_items nor next_page — treat as last page
            }
        }
        return out;
    }

    /** Extracts an endpoint id from one item of a {@code .../endpoints} response, defensively:
     *  tries a bare string entry first (some "list affected X" APIs return raw id strings rather
     *  than objects, unlike the main {@code /endpoints/managed} listing this codebase originally
     *  modeled the shape on), then the {@code id}/{@code endpoint_id} object fields. See the
     *  warning logged just above this method's only call site if none of these match a live
     *  tenant's actual shape — that log line's raw JSON is the fastest way to add the right key. */
    private static String endpointId(JsonNode item) {
        if (item.isTextual()) return item.asText(null);
        String id = item.path("id").asText(null);
        if (id != null && !id.isBlank()) return id;
        return item.path("endpoint_id").asText(null);
    }

    // ── Rate limiting ────────────────────────────────────────────────────────

    /** Sends {@code req}, retrying with backoff on a 429 instead of surfacing it as a sync
     *  failure — see class javadoc. Honors the SDK-documented {@code details.retry_after} field
     *  (seconds) when Action1 sends one; otherwise backs off exponentially from {@link
     *  #BASE_BACKOFF_MS} (2s, 4s, 8s, …), same as the official PSAction1 SDK. Gives up and
     *  returns the (still-429) response after {@link #MAX_RATE_LIMIT_RETRIES} attempts, letting
     *  the caller's own status-code check report the failure with a clear message. */
    private HttpResponse<String> sendWithRetry(HttpRequest req) throws Exception {
        int attempt = 0;
        while (true) {
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 429) return resp;
            attempt++;
            if (attempt > MAX_RATE_LIMIT_RETRIES) {
                log.warn("Action1 rate limit: giving up after {} attempts for {}", attempt - 1, req.uri());
                return resp;
            }
            long waitMs = retryAfterMs(resp.body());
            if (waitMs < 0) waitMs = BASE_BACKOFF_MS * (1L << (attempt - 1));
            log.warn("Action1 rate limit hit (attempt {}/{}) — waiting {}ms before retrying {}",
                attempt, MAX_RATE_LIMIT_RETRIES, waitMs, req.uri());
            Thread.sleep(waitMs);
        }
    }

    private long retryAfterMs(String body) {
        try {
            JsonNode retryAfter = objectMapper.readTree(body).path("details").path("retry_after");
            if (retryAfter.isIntegralNumber()) return retryAfter.asLong() * 1000L;
        } catch (Exception ignored) { /* fall through to exponential backoff */ }
        return -1;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String regionBase(String settingsJson) {
        String region = region(settingsJson);
        return REGIONS.getOrDefault(region, REGIONS.get(DEFAULT_REGION)).base();
    }

    private String region(String settingsJson) {
        if (settingsJson == null || settingsJson.isBlank()) return DEFAULT_REGION;
        try {
            String r = objectMapper.readTree(settingsJson).path("region").asText(null);
            return (r != null && !r.isBlank()) ? r : DEFAULT_REGION;
        } catch (Exception e) { return DEFAULT_REGION; }
    }

    private String orgId(String settingsJson) {
        if (settingsJson == null || settingsJson.isBlank())
            throw new IllegalStateException("Action1 integration has no orgId configured in its settings");
        String id;
        try {
            id = objectMapper.readTree(settingsJson).path("orgId").asText(null);
        } catch (Exception e) {
            throw new IllegalStateException("Action1 integration has an invalid settings JSON", e);
        }
        if (id == null || id.isBlank())
            throw new IllegalStateException("Action1 integration has no orgId configured in its settings");
        return id;
    }

    private HttpRequest get(String url, String token) {
        return HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", "Bearer " + token)
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(60))
            .GET().build();
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String snippet(String s, int max) {
        if (s == null) return "null";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
