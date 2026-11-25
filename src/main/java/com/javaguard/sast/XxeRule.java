package com.javaguard.sast;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects XML parsers (DocumentBuilderFactory, SAXParserFactory, XMLInputFactory)
 * that do not disable DOCTYPE / external entity processing (OWASP A05:2021 XXE).
 */
public class XxeRule implements SecurityRule {

    private static final Pattern XML_FACTORY_PATTERN = Pattern.compile(
        "(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\\.newInstance\\s*\\("
    );

    private static final String DISALLOW_DOCTYPE = "disallow-doctype-decl";
    private static final String SUPPORT_DTD = "javax.xml.stream.supportDTD";

    @Override
    public String ruleId() {
        return "JG-XXE-002";
    }

    @Override
    public List<SecurityFinding> scan(String fileName, String sourceCode) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (sourceCode == null || sourceCode.isBlank()) {
            return findings;
        }
        boolean hasHardening = sourceCode.contains(DISALLOW_DOCTYPE) || sourceCode.contains(SUPPORT_DTD);
        if (hasHardening) {
            return findings;
        }
        String[] lines = sourceCode.split("\\R");
        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("*")) {
                continue;
            }
            Matcher m = XML_FACTORY_PATTERN.matcher(lines[i]);
            if (m.find()) {
                findings.add(new SecurityFinding(
                    ruleId(),
                    "HIGH",
                    fileName,
                    i + 1,
                    "XML parser factory instantiated without disabling DOCTYPE declarations (XXE risk).",
                    trimmed
                ));
            }
        }
        return findings;
    }
}
