package com.example.gensignatureandroid;

import androidx.appcompat.app.AppCompatActivity;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
//import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String TAG = "MainActivity";
    private EditText etPackageName;
    private EditText tvSignature;

    private String md5 = "", sha1 = "", sha256 = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        etPackageName = (EditText) findViewById(R.id.et_package_name);
        tvSignature = (EditText) findViewById(R.id.tv_signature);
        findViewById(R.id.btn_get_signature).setOnClickListener(this);
        findViewById(R.id.btn_get_app_list).setOnClickListener(this);
    }

    @Override
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_get_signature:
                getSign(etPackageName.getText().toString());
                break;
            case R.id.btn_get_app_list:
                getAppList();
                break;
        }
    }

    public void getSign(String packageName) {

        try {

            PackageInfo pi = getPackageManager().getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            Signature signatures = pi.signatures[0];

            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(signatures.toByteArray());
            byte[] digest = md.digest();
            String res = toHexString(digest);
            Log.e(TAG, "apk MD5 = " + res);
            md5 = res;

            MessageDigest md2 = MessageDigest.getInstance("SHA1");
            md2.update(signatures.toByteArray());
            byte[] digest2 = md2.digest();
            String res2 = toHexString(digest2);
            Log.e(TAG, "apk SHA1 = " + res2);
            sha1 = res2;

            MessageDigest md3 = MessageDigest.getInstance("SHA256");
            md3.update(signatures.toByteArray());
            byte[] digest3 = md3.digest();
            String res3 = toHexString(digest3);
            Log.e(TAG, "apk SHA256 = " + res3);
            sha256 = res3;

            ByteArrayInputStream bais = new ByteArrayInputStream(signatures.toByteArray());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
            String sigAlgName = cert.getSigAlgName();
            String subjectDN = cert.getSubjectDN().toString();
            String issuerDN = cert.getIssuerDN().toString();
            int version = cert.getVersion();
            String serialNumber = cert.getSerialNumber().toString();
            String notBefore = cert.getNotBefore().toString();
            String notAfter = cert.getNotAfter().toString();
            String base64 = encodeBase64(signatures.toByteArray());

            Log.e(TAG, "sigAlgName = " + sigAlgName);
            Log.e(TAG, "subjectDN = " + subjectDN);
            Log.e(TAG, "issuerDN = " + issuerDN);

            StringBuilder builder = new StringBuilder();
            builder.append("\nsubjectDN(证书所有者) : ").append(subjectDN);
            builder.append("\nissuerDN(证书所有者) : ").append(issuerDN);
            builder.append("\nserialNumber(序列号) : ").append(serialNumber);
            builder.append("\nnotBefore(开始) : ").append(notBefore);
            builder.append("\nnotAfter(结束) : ").append(notAfter);

            builder.append("\n证书指纹:");
            builder.append("\n    MD5 : ").append(res);
            builder.append("\n    SHA1 : ").append(res2);
            builder.append("\n    SHA256 : ").append(res3);

            builder.append("\nsigAlgName(签名算法名称) : ").append(sigAlgName);
            builder.append("\nversion(版本) : ").append(version);
            builder.append("\n\n\nbase64 : \n").append(base64);
            builder.append("\ntargetSdkVersion :").append(pi.applicationInfo.targetSdkVersion);
            int targetSdkVersion = getApplicationContext().getApplicationInfo().targetSdkVersion;
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S){
                builder.append("\ncompileSdkVersion :").append(pi.applicationInfo.compileSdkVersion);
                builder.append("\ncompileSdkVersionCodename :").append(pi.applicationInfo.compileSdkVersionCodename);
            }
            builder.append("\nminSdkVersion :").append(pi.applicationInfo.minSdkVersion);
            builder.append("\nbaseRevisionCode :").append(pi.baseRevisionCode);
            builder.append("\nversionName :").append(pi.versionName);
            long appVersionCode = -1;
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P){
                appVersionCode = pi.getLongVersionCode();
            }else{
                appVersionCode = pi.versionCode;
            }
            builder.append("\nversionCode :").append(appVersionCode);
            builder.deleteCharAt(0);
            bais.close();
            tvSignature.setText(builder.toString());
        } catch (Exception e) {
            e.printStackTrace();
            md5 = sha1 = sha256 ="";
            tvSignature.setText(e.getMessage() + " \nsigns is null");
        }
    }

    public void getAppList(){
        StringBuilder builder = new StringBuilder();
        List<ApplicationInfo> allApps = getPackageManager().getInstalledApplications(0);
        List<String> packageNameList = new ArrayList<String>();
        for(ApplicationInfo ai : allApps){
            packageNameList.add(ai.packageName);
        }
        Collections.sort(packageNameList);
        for(String packageName : packageNameList){
            builder.append("\n" + packageName);
        }
        builder.deleteCharAt(0);
        tvSignature.setText(builder.toString());
    }

    /**
     * Converts a byte array to hex string
     *
     * @param block
     * @return
     */
    private String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }

    private void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    private static String encodeBase64(byte[] inputByte){
        if (inputByte == null) return null;
        try {
            byte[] b =Base64.encode(inputByte, Base64.DEFAULT);
            return new String(b);
        } catch (Exception e) {
            return null;
        }
    }

}
