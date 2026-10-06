package dev.checkstead.maven;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/** Thin goal: {@code checkstead scan} with the coordinates and jars Maven already resolved. */
@Mojo(
        name = "scan",
        defaultPhase = LifecyclePhase.VERIFY,
        requiresDependencyResolution = ResolutionScope.RUNTIME,
        threadSafe = true)
public class ScanMojo extends AbstractMojo {
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(property = "checkstead.executable", defaultValue = "checkstead")
    private String executable;

    @Parameter(property = "checkstead.config")
    private File config;

    @Parameter(property = "checkstead.output", defaultValue = "${project.build.directory}/checkstead-report")
    private File output;

    /** When set, scan this path instead of the resolved artifacts. */
    @Parameter(property = "checkstead.scan")
    private File scan;

    @Override
    public void execute() throws MojoExecutionException {
        List<String> scans = new ArrayList<>();
        if (scan != null) {
            scans.add(scan.getAbsolutePath());
        } else {
            Artifact main = project.getArtifact();
            if (main != null && main.getFile() != null && main.getFile().isFile()) {
                scans.add(main.getFile().getAbsolutePath());
            }
            if (project.getArtifacts() != null) {
                for (Artifact artifact : project.getArtifacts()) {
                    File file = artifact.getFile();
                    if (file != null && file.isFile()) {
                        scans.add(file.getAbsolutePath());
                    }
                }
            }
            if (scans.isEmpty() && project.getBasedir() != null) {
                scans.add(project.getBasedir().getAbsolutePath());
            }
        }
        String projectName = project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion();
        String configPath = config != null && config.isFile() ? config.getAbsolutePath() : null;
        List<String> command;
        try {
            command = ScanCommand.arguments(
                    executable, projectName, output.getAbsolutePath(), configPath, scans);
        } catch (IllegalArgumentException ex) {
            throw new MojoExecutionException(ex.getMessage(), ex);
        }
        getLog().info("checkstead scan " + projectName);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.inheritIO();
        builder.directory(project.getBasedir());
        Map<String, String> environment = builder.environment();
        environment.remove("NVD_API_KEY");
        environment.remove("NVD_APIKEY");
        try {
            int code = builder.start().waitFor();
            if (code != 0) {
                throw new MojoExecutionException("checkstead scan exited " + code);
            }
        } catch (MojoExecutionException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new MojoExecutionException("Unable to run checkstead scan", ex);
        }
    }
}
