package ru.iu3.fclient;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Arrays;

import ru.iu3.fclient.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'fclient' library on application startup.
    static {
        System.loadLibrary("fclient");
        System.loadLibrary("mbedcrypto");
        LOGFromJNI();
    }

    private ActivityMainBinding binding;

    @Override

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        initRng();

        byte[] keyRand1 = randomBytes(16);
        byte[] dataRand1 = randomBytes(16);
        byte[] dataRandEnc1 = encrypt(keyRand1, dataRand1);
        byte[] dataRandDenc1 = decrypt(keyRand1, dataRandEnc1);
        tv.setText(Arrays.toString(keyRand1) + Arrays.toString(dataRand1) +
                Arrays.toString(dataRandEnc1) + Arrays.toString(dataRandDenc1));
    }

    /**
     * A native method that is implemented by the 'fclient' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
    public static native void LOGFromJNI();
    public static native int initRng();
    public static native byte[] randomBytes(int no);
    public static native byte[] encrypt(byte[] key, byte[] data);
    public static native byte[] decrypt(byte[] key, byte[] data);
}