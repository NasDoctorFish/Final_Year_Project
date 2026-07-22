package com.bioauthguard.vulndemo;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;

/**
 * VULN (M3/M1): a DELIBERATELY leaky auth-state oracle.
 *
 * This exported, unguarded ContentProvider answers "is this identifier valid?" —
 * and, fatally, answers a VALID identifier differently from an invalid one:
 *   content://com.bioauthguard.vulndemo.tokens/admin  -> one row {status=valid}
 *   content://com.bioauthguard.vulndemo.tokens/nobody -> empty cursor (no rows)
 *
 * An unauthenticated caller can therefore enumerate valid identifiers / brute-force
 * a token purely from the distinguishable response — the classic error/enumeration
 * oracle side channel that BioAuthGuard's response_oracle detector catches over adb.
 * A secure provider would return an identical, generic response for every input
 * (and require a permission / real auth check).
 */
public class TokenCheckProvider extends ContentProvider {

    // The one "valid" identifier this toy oracle recognises.
    private static final String VALID_TOKEN = "admin";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"status"});
        String candidate = uri.getLastPathSegment();
        if (VALID_TOKEN.equals(candidate)) {
            // VULN: a positive, input-dependent response leaks that the token is valid.
            cursor.addRow(new Object[]{"valid"});
        }
        // Invalid candidate -> zero rows: `content query` prints "No result found.",
        // observably different from the valid case. That difference IS the oracle.
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.dir/vnd.com.bioauthguard.vulndemo.token";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
