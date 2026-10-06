package dev.checkstead.maven;

import java.util.ArrayList;
import java.util.List;

/** Arguments for the checkstead CLI. This plugin does not talk to Dependency-Check itself. */
public final class ScanCommand {
    private ScanCommand() {}

    public static List<String> arguments(
            String executable, String project, String output, String configOrNull, List<String> scanPaths) {
        if (scanPaths == null || scanPaths.isEmpty()) {
            throw new IllegalArgumentException("at least one scan path is required");
        }
        List<String> command = new ArrayList<>();
        command.add(executable);
        command.add("scan");
        command.add("--project");
        command.add(project);
        command.add("--out");
        command.add(output);
        if (configOrNull != null && !configOrNull.isEmpty()) {
            command.add("--config");
            command.add(configOrNull);
        }
        for (String path : scanPaths) {
            command.add("--scan");
            command.add(path);
        }
        return List.copyOf(command);
    }
}
