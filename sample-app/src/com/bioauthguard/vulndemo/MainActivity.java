package com.bioauthguard.vulndemo;

import android.app.Activity;
import android.content.Intent;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * The "login" screen. Shows a biometric prompt and, on success, opens the secret
 * screen. The biometric check is boolean-only (no CryptoObject binding) — the
 * classic weak pattern BioAuthGuard's static analyzer flags.
 */
public class MainActivity extends Activity {

    private static final String TAG = "BioAuthDemo";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 120, 48, 48);

        TextView title = new TextView(this);
        title.setText("BioAuthGuard VulnDemo\n\nLocked. Authenticate to view the secret.");
        title.setTextSize(18);
        root.addView(title);

        Button auth = new Button(this);
        auth.setText("Authenticate");
        auth.setOnClickListener(v -> authenticate());
        root.addView(auth);

        setContentView(root);

        // VULN (M9/M6): a session token is written to logcat in the clear.
        Log.i(TAG, "auth session token=SDF9sd8f7sdKJHkjh324kjhKJH234ZZaa11bb22cc33==");
    }

    private void authenticate() {
        BiometricPrompt prompt = new BiometricPrompt.Builder(this)
                .setTitle("Unlock VulnDemo")
                .setDescription("Prove it's you")
                .setNegativeButton("Cancel", getMainExecutor(), (dialog, which) -> { })
                .build();

        prompt.authenticate(new CancellationSignal(), getMainExecutor(),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        // VULN (M3/M10): the boolean success is trusted with no
                        // cryptographic key bound to the biometric.
                        Log.i(TAG, "Authentication succeeded — unlocking secret");
                        startActivity(new Intent(MainActivity.this, SecretActivity.class));
                    }
                });
    }
}
