package com.martecyber.plugins.action1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps Action1's {@code /vulnerabilities/{orgId}} + per-CVE {@code .../endpoints} results (see
 * {@link Action1Client#fetchVulnerabilities}) into one detection per (endpoint, CVE) pair.
 *
 * Host identity here is the same "action1-{endpointId}" external-id scheme {@link
 * Action1AssetParser} uses — this parser also emits a minimal HOST ParsedAsset per affected
 * endpoint (id-only, no hostname hint: the endpoints-by-CVE response carries no name field per
 * the SDK source) so a vuln-only sync run still creates a usable host. When an asset sync has
 * already run for this integration, core's host-resolution external-id lookup resolves this stub
 * straight to that already-named host instead of creating a duplicate.
 *
 * No "fixed" signal: Action1's vulnerability list appears to only ever return currently-active
 * CVEs (nothing in the public SDK source indicates a per-item terminal/patched state distinct
 * from the list's own filters) — every detection here is left at ParsedDetection's default state
 * (open/unknown), same choice TenableAssetParser-adjacent code makes when a tool gives no
 * explicit fixed/open signal.
 */
public class Action1VulnParser {

    private static final Logger log = LoggerFactory.getLogger(Action1VulnParser.class);
    private final ObjectMapper objectMapper;

    public Action1VulnParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ParseResult parseDetections(List<Action1Client.VulnWithEndpoints> vulns) {
        ParseResult result = new ParseResult();
        int count = 0;
        for (Action1Client.VulnWithEndpoints v : vulns) {
            for (String endpointId : v.endpointIds()) {
                emit(v.vuln(), endpointId, result);
                count++;
            }
        }
        log.info("Action1VulnParser: {} (endpoint, CVE) detection(s) from {} vulnerabilit(y/ies)",
            count, vulns.size());
        return result;
    }

    private boolean diagnosedOnce = false;

    private void emit(JsonNode vuln, String endpointId, ParseResult result) {
        String cveId = vuln.path("cve_id").asText(null);
        if (cveId == null || cveId.isBlank() || endpointId == null || endpointId.isBlank()) return;
        String hostId = "action1-" + endpointId.trim();

        Map<String, Object> hostMeta = new LinkedHashMap<>();
        hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_TOOL_KEY, "action1");
        hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_VALUE_KEY, endpointId.trim());
        result.addAsset(new ParsedAsset(hostId, AssetType.HOST, hostMeta));

        String name = vuln.path("name").asText(null);
        String title = (name != null && !name.isBlank()) ? name : cveId;
        java.math.BigDecimal cvssScore = findCvssScore(vuln);
        String severity = mapSeverity(vuln, cvssScore);
        if (!diagnosedOnce) {
            diagnosedOnce = true;
            log.warn("Action1 DIAGNOSTIC — raw vulnerability item (mapped severity={}, cvssScore={}): {}",
                severity, cvssScore, vuln);
        }

        // Stores the ENTIRE raw item, not a curated subset of guessed field names — the "name"/
        // "score" fields this parser reads are unverified against a live tenant (see class
        // javadoc), so a curated rawData would just reproduce the same guesses instead of giving
        // an operator real ground truth to check straight from the Detection's own raw_data.
        String rawData;
        try { rawData = objectMapper.writeValueAsString(vuln); } catch (Exception e) { rawData = vuln.toString(); }

        ParsedDetection pd = new ParsedDetection(title, severity, null, hostId, cveId, rawData);
        if (cvssScore != null) {
            pd.setCvssScore(cvssScore);
            pd.setCvssVersion("CVSS 3.1"); // Action1 doesn't document which CVSS version its score is — 3.1 is the common default; correct once confirmed
        }
        result.addDetection(pd);
    }

    /** Tries the same numeric-score field candidates {@link #mapSeverity} falls back to, for
     *  reuse as the detection's actual CVSS value (not just a severity bucket) — see that
     *  method's own doc for why the field name is unverified.
     *
     *  Confirmed against real tenant data: Action1's API returns {@code cvss_score} (and
     *  apparently every other numeric-looking field — {@code endpoints_count}, etc.) as a
     *  JSON STRING (e.g. {@code "cvss_score": "7.8"}), not a JSON number — so {@code
     *  n.isNumber()} alone silently missed it on every real vuln, leaving severity to fall
     *  through to "info" whenever (as is typical) the string {@code score}/{@code severity}
     *  fields also aren't present. Both representations are tried here. */
    private static java.math.BigDecimal findCvssScore(JsonNode vuln) {
        for (String numericField : new String[] {"cvss_score", "cvss", "base_score", "risk_score"}) {
            JsonNode n = vuln.path(numericField);
            if (n.isNumber()) return java.math.BigDecimal.valueOf(n.asDouble());
            if (n.isTextual()) {
                try { return new java.math.BigDecimal(n.asText().trim()); }
                catch (NumberFormatException ignored) { /* not parseable — try the next field */ }
            }
        }
        return null;
    }

    /** CVSS-first: when Action1 gives a numeric CVSS score ({@link #findCvssScore}), that's the
     *  authoritative basis, bucketed via the same standard CVSS severity bands every other
     *  integration in this codebase uses ({@link #bucketByCvss}) — not Action1's own {@code
     *  score}/{@code severity} string fields, whose exact enum values were never verified against
     *  a live tenant (same category of gap as {@code Action1Client#endpointId}, which turned out
     *  to need its own fallback). Those string fields are now fallback-only, used only when no
     *  numeric CVSS value is present at all. */
    private static String mapSeverity(JsonNode vuln, java.math.BigDecimal cvssScore) {
        if (cvssScore != null) return bucketByCvss(cvssScore.doubleValue());
        String bucketed = bucketLabel(vuln.path("score").asText(null));
        if (bucketed != null) return bucketed;
        bucketed = bucketLabel(vuln.path("severity").asText(null));
        if (bucketed != null) return bucketed;
        return "info";
    }

    private static String bucketLabel(String label) {
        if (label == null) return null;
        return switch (label.trim().toLowerCase()) {
            case "critical" -> "critical";
            case "high" -> "high";
            case "medium", "moderate" -> "medium";
            case "low" -> "low";
            default -> null; // unrecognized — let the caller try the next candidate field
        };
    }

    private static String bucketByCvss(double score) {
        if (score >= 9.0) return "critical";
        if (score >= 7.0) return "high";
        if (score >= 4.0) return "medium";
        if (score > 0.0) return "low";
        return "info";
    }
}
