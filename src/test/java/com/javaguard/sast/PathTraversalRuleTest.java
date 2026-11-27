package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class PathTraversalRuleTest {

    private final PathTraversalRule rule = new PathTraversalRule();

    @Test
    void detectsUnvalidatedPathsGetSink() {
        String code = """
            public String readUpload(String fileName) throws IOException {
                return Files.readString(Paths.get("/var/uploads", fileName));
            }
            """;
        List<SecurityFinding> findings = rule.scan("UploadService.java", code);
        assertEquals(1, findings.size());
        assertEquals("JG-PATH-007", findings.get(0).ruleId());
    }

    @Test
    void allowsNormalizedStartsWithGuard() {
        String code = """
            Path base = Paths.get("/var/uploads").toAbsolutePath().normalize();
            Path target = base.resolve(fileName).normalize();
            if (!target.startsWith(base)) throw new SecurityException("Traversal");
            return Files.readString(target);
            """;
        List<SecurityFinding> findings = rule.scan("UploadService.java", code);
        assertTrue(findings.isEmpty());
    }
}
