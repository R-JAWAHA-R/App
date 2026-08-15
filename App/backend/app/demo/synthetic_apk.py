import os
import zipfile


def create_synthetic_test_apk(output_path: str, apk_type: str = "banking_trojan") -> str:
    """
    Creates a safe, synthetic APK archive containing realistic AndroidManifest.xml,
    classes.dex, and asset strings for testing the forensic pipeline without running malware.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    if apk_type == "banking_trojan":
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.sbi.rewards.yono.update"
    android:versionCode="1"
    android:versionName="2.4.1">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <application
        android:allowBackup="true"
        android:icon="@drawable/sbi_icon"
        android:label="SBI Rewards Update"
        android:theme="@style/AppTheme">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".AccessibilityStealerService"
            android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
            android:exported="true">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService" />
            </intent-filter>
        </service>
        <receiver android:name=".SMSBroadcastReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SMS_RECEIVED" />
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""
        dex_strings = (
            "https://sbi-rewards-bonus.top/api/v2/gate "
            "https://update-yono-kyc.xyz/auth/login "
            "https://api.telegram.org/bot7182938102:AAF9x_FakeTokenSBI_exfil/sendMessage "
            "com.sbi.lotus.integra netbanking mpin yono sbi debit card cvv "
            "DexClassLoader Class.forName getDeclaredMethod Base64.decode AES/CBC/PKCS5Padding "
            "AccessibilityNodeInfo TYPE_VIEW_TEXT_CHANGED AccessibilityService "
            "WindowManager.addView TYPE_APPLICATION_OVERLAY SmsManager.sendTextMessage "
            "185.220.101.5 194.26.29.110"
        )
    elif apk_type == "loan_spyware":
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.fastcash.loan.instant"
    android:versionCode="10"
    android:versionName="1.0.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <application android:label="FastCash Instant Loans">
        <activity android:name=".LoanApplyActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        dex_strings = (
            "https://fastloan-api-in.live/uploadContacts "
            "https://fastloan-api-in.live/syncDeviceData "
            "ContentResolver.query content://com.android.contacts/contacts "
            "CameraManager.openCamera uploadGallery syncExtortionData 194.26.29.110"
        )
    else:
        # Clean utility app
        manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.clean.tools.calculator"
    android:versionCode="3"
    android:versionName="1.2.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="SafeCalculator Pro">
        <activity android:name=".CalcActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        dex_strings = "https://analytics.safecalculator.com/ping SharedPreferences.getString Activity.onCreate"

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest_content.encode("utf-8"))
        z.writestr("classes.dex", dex_strings.encode("utf-8"))
        z.writestr("resources.arsc", b"\x02\x00\x0C\x00" + dex_strings.encode("utf-8"))
        z.writestr("assets/app_config.json", b'{"api_endpoint": "https://api.gateway.local"}')

    return output_path
