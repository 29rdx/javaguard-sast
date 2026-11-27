package com.javaguard.sast;

import java.util.List;

/**
 * Exports JavaGuard SAST findings to SARIF 2.1.0 JSON format
 * compatible with GitHub Code Scanning.
 */
public class SarifExporter {

    public String toSarifJson(List<SecurityFinding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
        sb.append("  \"version\": \"2.1.0\",\n");
        sb.append("  \"runs\": [\n");
        sb.append("    {\n");
        sb.append("      \"tool\": {\n");
        sb.append("        \"driver\": {\n");
        sb.append("          \"name\": \"JavaGuard SAST\",\n");
        sb.append("          \"version\": \"0.1.0\"\n");
        sb.append("        }\n");
        sb.append("      },\n");
        sb.append("      \"results\": [\n");

        for (int i = 0; i < findings.size(); i++) {
            SecurityFinding f = findings.get(i);
            String level = switch (f.severity().toUpperCase()) {
                case "CRITICAL", "HIGH" -> "error";
                case "MEDIUM" -> "warning";
                default -> "note";
            };
            sb.append("        {\n");
            sb.append("          \"ruleId\": \"").append(escapeJson(f.ruleId())).append("\",\n");
            sb.append("          \"level\": \"").append(level).append("\",\n");
            sb.append("          \"message\": { \"text\": \"").append(escapeJson(f.message())).append("\" },\n");
            sb.append("          \"locations\": [{\n");
            sb.append("            \"physicalLocation\": {\n");
            sb.append("              \"artifactLocation\": { \"uri\": \"").append(escapeJson(f.fileName())).append("\" },\n");
            sb.append("              \"region\": { \"startLine\": ").append(f.lineNumber()).append(" }\n");
            sb.append("            }\n");
            sb.append("          }]\n");
            sb.append("        }").append(i + 1 < findings.size() ? "," : "").append("\n");
        }

        sb.append("      ]\n");
        sb.append("    }\n");
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
