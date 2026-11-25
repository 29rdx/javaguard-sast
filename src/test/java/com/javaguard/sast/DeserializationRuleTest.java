package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DeserializationRuleTest {

    private final DeserializationRule rule = new DeserializationRule();

    @Test
    void detectsUnfilteredObjectInputStream() {
        String code = """
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            Object obj = ois.readObject();
            """;
        List<SecurityFinding> findings = rule.scan("SessionReader.java", code);
        assertEquals(2, findings.size());
        assertEquals("JG-DESER-003", findings.get(0).ruleId());
        assertEquals("CRITICAL", findings.get(0).severity());
    }

    @Test
    void allowsObjectInputStreamWithObjectInputFilter() {
        String code = """
            ObjectInputStream ois = new ObjectInputStream(inputStream);
            ois.setObjectInputFilter(info -> ObjectInputFilter.Status.ALLOWED);
            return ois.readObject();
            """;
        List<SecurityFinding> findings = rule.scan("SessionReader.java", code);
        assertTrue(findings.isEmpty());
    }
}
