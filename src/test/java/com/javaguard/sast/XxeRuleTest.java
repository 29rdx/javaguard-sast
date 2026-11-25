package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class XxeRuleTest {

    private final XxeRule rule = new XxeRule();

    @Test
    void detectsUnhardenedDocumentBuilderFactory() {
        String code = """
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            Document doc = dbf.newDocumentBuilder().parse(inputStream);
            """;
        List<SecurityFinding> findings = rule.scan("XmlLoader.java", code);
        assertEquals(1, findings.size());
        assertEquals("JG-XXE-002", findings.get(0).ruleId());
        assertEquals("HIGH", findings.get(0).severity());
    }

    @Test
    void allowsHardenedDocumentBuilderFactory() {
        String code = """
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            """;
        List<SecurityFinding> findings = rule.scan("XmlLoader.java", code);
        assertTrue(findings.isEmpty());
    }
}
