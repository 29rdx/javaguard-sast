package com.javaguard.sast;

import java.util.List;

public interface SecurityRule {
    String ruleId();
    List<SecurityFinding> scan(String fileName, String sourceCode);
}
