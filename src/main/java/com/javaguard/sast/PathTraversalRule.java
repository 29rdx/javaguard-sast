package com.javaguard.sast;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects file-system path sinks (Paths.get, new File, Files.readString/write)
 * that lack .normalize() + .startsWith(...) canonicalization checks (OWASP A01:2021).
 */
public class PathTraversalRule implements SecurityRule {

    private static final Pattern PATH_SINK = Pattern.compile(
        "(Paths\\.get|Path\\.of|new\\s+File|Files\\.(readString|readAllBytes|write|newInputStream))\\s*\\("
    );

    @Override
    public String ruleId() {
        return "JG-PATH-007";
    }

    @Override
    public List<SecurityFinding> scan(String fileName, String sourceCode) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (sourceCode == null || sourceCode.isBlank()) {
            return findings;
        }
        boolean hasCanonicalCheck = sourceCode.contains(".normalize()") && sourceCode.contains(".startsWith(");
        if (hasCanonicalCheck) {
            return findings;
        }
        String[] lines = sourceCode.split("\\R");
        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("*")) {
                continue;
            }
            Matcher m = PATH_SINK.matcher(lines[i]);
            if (m.find()) {
                findings.add(new SecurityFinding(
                    ruleId(),
                    "HIGH",
                    fileName,
                    i + 1,
                    "File path sink without .normalize().startsWith() canonicalization guard (Path Traversal risk).",
                    trimmed
                ));
            }
        }
        return findings;
    }
}
