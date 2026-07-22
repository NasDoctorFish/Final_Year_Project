package com.bioauthguard.vulndemo;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * The "protected" screen that is supposed to be reachable only after a successful
 * biometric authentication — but it is exported with no permission, so anyone (and
 * BioAuthGuard's IPC oracle) can launch it directly with `am start`, bypassing the
 * gate. It also leaks a secret to logcat on entry.
 */
public class SecretActivity extends Activity {

    private static final String TAG = "BioAuthDemo";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setText("🔓 SECRET SCREEN\n\nThis should require biometric auth —\n"
                + "but the activity is exported, so it opened without it.");
        tv.setTextSize(18);
        tv.setPadding(48, 120, 48, 48);
        setContentView(tv);

        // VULN (M9/M6): sensitive post-auth material dumped to logcat.
        Log.i(TAG, "auth token=TOPSECRET_9f8a7b6c5d4e3f2a1b0c_SESSION_AUTHENTICATED_OK_do_not_log_this");
    }
}
