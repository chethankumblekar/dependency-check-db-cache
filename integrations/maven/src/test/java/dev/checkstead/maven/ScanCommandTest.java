package dev.checkstead.maven;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class ScanCommandTest {
    @Test
    void callsChecksteadScanWithCoordinatesAndJars() {
        List<String> command = ScanCommand.arguments(
                "checkstead",
                "dev.example:demo:1.2.3",
                "/tmp/out",
                "/tmp/checkstead.yml",
                List.of("/home/dev/.m2/repository/dev/example/demo/1.2.3/demo-1.2.3.jar"));

        assertEquals("checkstead", command.get(0));
        assertEquals("scan", command.get(1));
        assertTrue(command.contains("--project"));
        assertTrue(command.contains("dev.example:demo:1.2.3"));
        assertTrue(command.contains("--scan"));
        assertTrue(command.contains("/home/dev/.m2/repository/dev/example/demo/1.2.3/demo-1.2.3.jar"));
        assertFalse(command.contains("--nvdApiKey"));
        assertFalse(command.contains("services.nvd.nist.gov"));
        assertFalse(String.join(" ", command).contains("nvdApiKey"));
    }
}
