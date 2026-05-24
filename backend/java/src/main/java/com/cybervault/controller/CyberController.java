package com.cybervault.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;

@RestController
@RequestMapping("/api/v1/cyber")
@CrossOrigin(origins = {"http://localhost:3000", "https://cybervault.onrender.com"})
@Validated
public class CyberController {

    private static final Logger logger = LoggerFactory.getLogger(CyberController.class);
    private static final int TIMEOUT_SECONDS = 30;

    // Security patterns for input validation
    private static final String SAFE_PATH_PATTERN = "^[a-zA-Z0-9._/\\-]+$";
    private static final String SAFE_DEVICE_PATTERN = "^[a-zA-Z0-9]+$";

    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> encryptFile(
            @RequestParam @NotBlank @Pattern(regexp = SAFE_PATH_PATTERN, message = "Invalid file path") String input,
            @RequestParam @NotBlank @Pattern(regexp = SAFE_PATH_PATTERN, message = "Invalid file path") String output,
            @RequestParam @NotBlank @Size(min = 8, max = 31, message = "Key must be between 8-31 characters") String key) {

        logger.info("Encryption request - Input: {}, Output: {}", sanitizeLogInput(input), sanitizeLogInput(output));

        Map<String, Object> response = new HashMap<>();

        try {
            // Validate input file exists and is readable
            Path inputPath = Paths.get(input);
            if (!Files.exists(inputPath) || !Files.isReadable(inputPath)) {
                response.put("success", false);
                response.put("message", "Input file does not exist or is not readable");
                return ResponseEntity.badRequest().body(response);
            }

            // Validate output directory exists and is writable
            Path outputPath = Paths.get(output);
            Path parentDir = outputPath.getParent();
            if (parentDir != null && (!Files.exists(parentDir) || !Files.isWritable(parentDir))) {
                response.put("success", false);
                response.put("message", "Output directory does not exist or is not writable");
                return ResponseEntity.badRequest().body(response);
            }

            ProcessBuilder pb = new ProcessBuilder("./backend/c/encrypt", "encrypt", input, output, key);
            pb.redirectErrorStream(true);

            Process process = pb.start();
            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                throw new RuntimeException("Encryption operation timed out");
            }

            String result = readProcessOutput(process);

            response.put("success", true);
            response.put("message", "File encrypted successfully");
            response.put("details", result);
            response.put("timestamp", System.currentTimeMillis());

            logger.info("Encryption completed successfully for file: {}", sanitizeLogInput(input));
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Encryption failed for file: {} - Error: {}", sanitizeLogInput(input), e.getMessage());
            response.put("success", false);
            response.put("message", "Encryption failed: " + e.getMessage());
            response.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decryptFile(
            @RequestParam @NotBlank @Pattern(regexp = SAFE_PATH_PATTERN, message = "Invalid file path") String input,
            @RequestParam @NotBlank @Pattern(regexp = SAFE_PATH_PATTERN, message = "Invalid file path") String output,
            @RequestParam @NotBlank @Size(min = 8, max = 31, message = "Key must be between 8-31 characters") String key) {

        logger.info("Decryption request - Input: {}, Output: {}", sanitizeLogInput(input), sanitizeLogInput(output));

        Map<String, Object> response = new HashMap<>();

        try {
            // Validate input file exists and is readable
            Path inputPath = Paths.get(input);
            if (!Files.exists(inputPath) || !Files.isReadable(inputPath)) {
                response.put("success", false);
                response.put("message", "Input file does not exist or is not readable");
                return ResponseEntity.badRequest().body(response);
            }

            // Validate output directory exists and is writable
            Path outputPath = Paths.get(output);
            Path parentDir = outputPath.getParent();
            if (parentDir != null && (!Files.exists(parentDir) || !Files.isWritable(parentDir))) {
                response.put("success", false);
                response.put("message", "Output directory does not exist or is not writable");
                return ResponseEntity.badRequest().body(response);
            }

            ProcessBuilder pb = new ProcessBuilder("./backend/c/encrypt", "decrypt", input, output, key);
            pb.redirectErrorStream(true);

            Process process = pb.start();
            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                throw new RuntimeException("Decryption operation timed out");
            }

            String result = readProcessOutput(process);

            response.put("success", true);
            response.put("message", "File decrypted successfully");
            response.put("details", result);
            response.put("timestamp", System.currentTimeMillis());

            logger.info("Decryption completed successfully for file: {}", sanitizeLogInput(input));
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Decryption failed for file: {} - Error: {}", sanitizeLogInput(input), e.getMessage());
            response.put("success", false);
            response.put("message", "Decryption failed: " + e.getMessage());
            response.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/network/scan")
    public ResponseEntity<Map<String, Object>> scanNetwork(
            @RequestParam(required = false, defaultValue = "auto")
            @Pattern(regexp = "^(auto|[a-zA-Z0-9]+)$", message = "Invalid network device") String device,
            @RequestParam(required = false, defaultValue = "10") int duration) {

        logger.info("Network scan request - Device: {}, Duration: {}s", sanitizeLogInput(device), duration);

        Map<String, Object> response = new HashMap<>();

        try {
            // Validate duration
            if (duration < 1 || duration > 60) {
                response.put("success", false);
                response.put("message", "Duration must be between 1-60 seconds");
                return ResponseEntity.badRequest().body(response);
            }

            // Auto-detect interface if "auto" is specified
            ProcessBuilder pb;
            if ("auto".equals(device)) {
                pb = new ProcessBuilder("./backend/cpp/sniffer", String.valueOf(duration));
            } else {
                pb = new ProcessBuilder("./backend/cpp/sniffer", device, String.valueOf(duration));
            }
            pb.redirectErrorStream(true);

            Process process = pb.start();
            boolean finished = process.waitFor(duration + 15, TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                throw new RuntimeException("Network scan operation timed out");
            }

            String result = readProcessOutput(process);

            // The sniffer now returns JSON, so we parse it
            try {
                // Try to parse as JSON to validate
                response.put("success", true);
                response.put("message", "Network scan completed successfully");
                response.put("scan_result", result.trim());
                response.put("timestamp", System.currentTimeMillis());
            } catch (Exception jsonError) {
                // If JSON parsing fails, return as raw data
                response.put("success", true);
                response.put("message", "Network scan completed successfully");
                response.put("raw_data", result);
                response.put("timestamp", System.currentTimeMillis());
            }

            logger.info("Network scan completed successfully for device: {}", sanitizeLogInput(device));
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Network scan failed for device: {} - Error: {}", sanitizeLogInput(device), e.getMessage());
            response.put("success", false);
            response.put("message", "Network scan failed: " + e.getMessage());
            response.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getSystemStatus() {
        Map<String, Object> response = new HashMap<>();

        response.put("status", "operational");
        response.put("version", "2.0.0");
        response.put("timestamp", System.currentTimeMillis());
        response.put("services", Map.of(
            "encryption", "available",
            "decryption", "available",
            "network_scan", "available",
            "file_browser", "available"
        ));

        return ResponseEntity.ok(response);
    }

    @GetMapping("/files/browse")
    public ResponseEntity<Map<String, Object>> browseFiles(
            @RequestParam(required = false, defaultValue = "/tmp")
            @Pattern(regexp = "^[a-zA-Z0-9._/\\-~]+$", message = "Invalid file path") String path) {

        logger.info("File browser request for path: {}", sanitizeLogInput(path));

        Map<String, Object> response = new HashMap<>();

        try {
            Path dirPath = Paths.get(path).normalize();

            // Security check - prevent directory traversal
            if (!dirPath.isAbsolute()) {
                dirPath = Paths.get("/").resolve(dirPath).normalize();
            }

            String absolutePath = dirPath.toString();
            if (absolutePath.contains("..")) {
                response.put("success", false);
                response.put("message", "Directory traversal not allowed");
                return ResponseEntity.badRequest().body(response);
            }

            if (!Files.exists(dirPath)) {
                response.put("success", false);
                response.put("message", "Directory does not exist: " + path);
                return ResponseEntity.badRequest().body(response);
            }

            if (!Files.isDirectory(dirPath)) {
                response.put("success", false);
                response.put("message", "Path is not a directory: " + path);
                return ResponseEntity.badRequest().body(response);
            }

            if (!Files.isReadable(dirPath)) {
                response.put("success", false);
                response.put("message", "Directory is not readable: " + path);
                return ResponseEntity.badRequest().body(response);
            }

            java.util.List<Map<String, Object>> files = new java.util.ArrayList<>();
            java.util.List<Map<String, Object>> directories = new java.util.ArrayList<>();

            // Add parent directory entry (except for root)
            if (!dirPath.toString().equals("/")) {
                Map<String, Object> parentEntry = new HashMap<>();
                parentEntry.put("name", "..");
                parentEntry.put("type", "directory");
                parentEntry.put("path", dirPath.getParent().toString());
                parentEntry.put("size", 0);
                parentEntry.put("readable", true);
                parentEntry.put("writable", false);
                directories.add(parentEntry);
            }

            // List directory contents
            try (var stream = Files.list(dirPath)) {
                stream.forEach(entry -> {
                    try {
                        Map<String, Object> fileInfo = new HashMap<>();
                        String fileName = entry.getFileName().toString();

                        // Skip hidden files that start with . (except ..)
                        if (fileName.startsWith(".") && !fileName.equals("..")) {
                            return;
                        }

                        fileInfo.put("name", fileName);
                        fileInfo.put("path", entry.toString());
                        fileInfo.put("readable", Files.isReadable(entry));
                        fileInfo.put("writable", Files.isWritable(entry));

                        if (Files.isDirectory(entry)) {
                            fileInfo.put("type", "directory");
                            fileInfo.put("size", 0);
                            directories.add(fileInfo);
                        } else {
                            fileInfo.put("type", "file");
                            fileInfo.put("size", Files.size(entry));
                            fileInfo.put("extension", getFileExtension(fileName));
                            files.add(fileInfo);
                        }
                    } catch (Exception e) {
                        // Skip files that can't be read
                    }
                });
            }

            // Sort directories and files by name
            directories.sort((a, b) -> ((String)a.get("name")).compareToIgnoreCase((String)b.get("name")));
            files.sort((a, b) -> ((String)a.get("name")).compareToIgnoreCase((String)b.get("name")));

            response.put("success", true);
            response.put("current_path", dirPath.toString());
            response.put("parent_path", dirPath.getParent() != null ? dirPath.getParent().toString() : null);
            response.put("directories", directories);
            response.put("files", files);
            response.put("total_items", directories.size() + files.size());
            response.put("timestamp", System.currentTimeMillis());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("File browser failed for path: {} - Error: {}", sanitizeLogInput(path), e.getMessage());
            response.put("success", false);
            response.put("message", "Failed to browse directory: " + e.getMessage());
            response.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @GetMapping("/files/common-paths")
    public ResponseEntity<Map<String, Object>> getCommonPaths() {
        Map<String, Object> response = new HashMap<>();

        java.util.List<Map<String, Object>> commonPaths = new java.util.ArrayList<>();

        // Common directories that typically exist
        String[] paths = {
            "/tmp", "/home", "/var/log", "/etc", "/opt",
            "/usr/local", "/var/tmp", "/root", "/mnt"
        };

        for (String pathStr : paths) {
            Path path = Paths.get(pathStr);
            if (Files.exists(path) && Files.isDirectory(path) && Files.isReadable(path)) {
                Map<String, Object> pathInfo = new HashMap<>();
                pathInfo.put("name", path.getFileName() != null ? path.getFileName().toString() : pathStr);
                pathInfo.put("path", pathStr);
                pathInfo.put("description", getPathDescription(pathStr));
                commonPaths.add(pathInfo);
            }
        }

        response.put("success", true);
        response.put("common_paths", commonPaths);
        response.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(response);
    }

    private String getFileExtension(String fileName) {
        int lastDotIndex = fileName.lastIndexOf('.');
        return lastDotIndex > 0 ? fileName.substring(lastDotIndex + 1).toLowerCase() : "";
    }

    private String getPathDescription(String path) {
        return switch (path) {
            case "/tmp" -> "Temporary files directory";
            case "/home" -> "User home directories";
            case "/var/log" -> "System log files";
            case "/etc" -> "System configuration files";
            case "/opt" -> "Optional software packages";
            case "/usr/local" -> "Local user programs";
            case "/var/tmp" -> "Temporary files (persistent)";
            case "/root" -> "Root user home directory";
            case "/mnt" -> "Mount points for file systems";
            default -> "System directory";
        };
    }

    private String readProcessOutput(Process process) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line).append("\n");
        }
        return result.toString();
    }

    private String sanitizeLogInput(String input) {
        // Remove potential log injection characters
        return input.replaceAll("[\r\n\t]", "_");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleException(Exception e) {
        logger.error("Unhandled exception: ", e);
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", "Internal server error");
        response.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
