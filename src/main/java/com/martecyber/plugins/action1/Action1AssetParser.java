package com.martecyber.plugins.action1;

import com.fasterxml.jackson.databind.JsonNode;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps Action1's {@code /endpoints/managed/{orgId}} results into HOST assets. Unlike Qualys/
 * Tenable, Action1's endpoint inventory carries no IP address at all (confirmed against the
 * official SDK source — it's an agent/hostname-centric RMM, not a network scanner) — every host
 * here is created purely from its Action1 endpoint id (as the external-id dedup key, see {@link
 * AssetMetadataKeys#EXTERNAL_ID_TOOL_KEY}) and name (as a hostname hint), with no INTERFACE/IP
 * assets or links at all. Core's host-resolution logic already supports this — the IP/interface
 * chain there is only ever consulted when a parse-time identifier happens to carry one; it's not a
 * requirement for host creation.
 */
public class Action1AssetParser {

    private static final Logger log = LoggerFactory.getLogger(Action1AssetParser.class);

    public ParseResult parseAssets(List<JsonNode> endpoints) {
        ParseResult result = new ParseResult();
        int emitted = 0;
        for (JsonNode ep : endpoints) {
            if (emit(ep, result)) emitted++;
        }
        log.info("Action1AssetParser: {} of {} endpoints emitted (rest had no id)", emitted, endpoints.size());
        return result;
    }

    private boolean emit(JsonNode ep, ParseResult result) {
        String id = ep.path("id").asText(null);
        if (id == null || id.isBlank()) return false;

        String name = ep.path("name").asText(null);
        Map<String, Object> hostMeta = new LinkedHashMap<>();
        if (name != null && !name.isBlank()) hostMeta.put(AssetMetadataKeys.HOSTNAME_HINTS_KEY, List.of(name.trim()));
        hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_TOOL_KEY, "action1");
        hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_VALUE_KEY, id.trim());

        String os = ep.path("OS").asText(null);
        if (os != null && !os.isBlank()) hostMeta.put("os", os.trim());
        String status = ep.path("status").asText(null);
        if (status != null && !status.isBlank()) hostMeta.put("action1Status", status.trim());

        result.addAsset(new ParsedAsset("action1-" + id.trim(), AssetType.HOST, hostMeta));
        return true;
    }
}
