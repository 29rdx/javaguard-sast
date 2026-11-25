package com.javaguard.sast;

public record SecurityFinding(
    String ruleId,
    String severity,
    String fileName,
    int lineNumber,
    String message,
    String snippet
) {}
