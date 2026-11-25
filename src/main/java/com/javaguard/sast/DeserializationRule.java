package com.javaguard.sast;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects unsafe Java ObjectInputStream deserialization without an
 * ObjectInputFilter or look-ahead class allowlist (OWASP A08:2021).
 */
public class DeserializationRule implements SecurityRule {

    private static final Pattern OIS_PATTERN = Pattern.compile(
        "(new\\s+ObjectInputStream\\s*\\(|\\.readObject\\s*\\(|\\.readUnshared\\s*\\()"
    );

    @Override
    public String ruleId() {
        return "JG-DESER-003";
    }

    @Override
    public List<SecurityFinding> scan(String fileName, String sourceCode) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (sourceCode == null || sourceCode.isBlank()) {
            return findings;
        }
        boolean hasFilter = sourceCode.contains("setObjectInputFilter")
            || sourceCode.contains("ObjectInputFilter");
        if (hasFilter) {
            return findings;
        }
        String[] lines = sourceCode.split("\\R");
        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("*")) {
                continue;
            }
            Matcher m = OIS_PATTERN.matcher(lines[i]);
            if (m.find()) {
                findings.add(new SecurityFinding(
                    ruleId(),
                    "CRITICAL",
                    fileName,
                    i + 1,
                    "Unsafe ObjectInputStream deserialization without ObjectInputFilter allowlist.",
                    trimmed
                ));
            }
        }
        return findings;
    }
}
