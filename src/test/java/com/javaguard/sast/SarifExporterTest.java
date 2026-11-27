package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class SarifExporterTest {

    @Test
    void exportsValidSarif210StructureWithEscaping() {
        SarifExporter exporter = new SarifExporter();
        List<SecurityFinding> findings = List.of(
            new SecurityFinding("JG-SQLI-001", "CRITICAL", "src/Dao.java", 42, "SQL \"concat\" detected", "stmt.execute()")
        );
        String sarif = exporter.toSarifJson(findings);
        assertTrue(sarif.contains("\"version\": \"2.1.0\""));
        assertTrue(sarif.contains("\"ruleId\": \"JG-SQLI-001\""));
        assertTrue(sarif.contains("\"level\": \"error\""));
        assertTrue(sarif.contains("\"startLine\": 42"));
        assertTrue(sarif.contains("SQL \\\"concat\\\" detected"));
    }
}
