# Alibaba UTDID SDK - Internal Architecture

Based on reverse engineering research from multiple sources:

## Key Classes (com.ta.utdid2.*)

### UTDevice.java
```java
public class UTDevice {
    public static String getUtdid(Context context) {
        // 1. Try Settings.System "mqBRboGZkQPcAkyk" 
        // 2. Try Settings.System "dxCRMxhQkdGePGnp" (AES encrypted)
        // 3. Try SharedPreferences "Alvin2"
        // 4. Try SharedPreferences "ContextData" key "K_1171477665"
        // 5. Generate new UTDID if all fail
        return UTUtdid.getValue();
    }
}
```

### UTUtdid.java
```java  
public class UTUtdid {
    // UTDID format: 24 characters, Base64-like
    // Example: "YKxAFCu0Z2sTABhvJsMy1234"
    
    public static String generateUtdid() {
        // Components:
        // - Timestamp (4 bytes)
        // - Random (4 bytes) 
        // - Device hash (4 bytes)
        // - Checksum (2 bytes)
        // Total: 14 bytes -> Base64 -> 24 chars
    }
}
```

## File Storage (.gs_fs0)

The .gs_fs0 directory uses a different mechanism than SharedPreferences:

### Storage Manager (GenericFileStorage)
```java
class GenericFileStorage {
    private static final String DIR = ".gs";
    private static final String SUBDIR = ".gs_fs0";
    
    // Files are named _0.jpg through _12.jpg
    // "a.jpg" is a marker file
    
    void write(String key, byte[] value) {
        // 1. Serialize value
        // 2. Encrypt with AES-128-CBC
        // 3. Encode with Base94
        // 4. Write to file
    }
}
```

## Encryption Details

### Key Derivation
```java
byte[] deriveKey(Context ctx) {
    String packageName = ctx.getPackageName();
    String androidId = Settings.Secure.getString(
        ctx.getContentResolver(), 
        Settings.Secure.ANDROID_ID
    );
    
    // Key = MD5(packageName + androidId + SALT)
    // SALT is hardcoded in native library
}
```

### AES Encryption
```java
byte[] encrypt(byte[] data, byte[] key) {
    // AES-128-CBC
    // IV = first 16 bytes of MD5(key)
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(
        Arrays.copyOf(MessageDigest.getInstance("MD5").digest(key), 16)
    );
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    return cipher.doFinal(data);
}
```

### Base94 Encoding
```java
// Custom Base94 alphabet (printable ASCII 32-125)
static final String ALPHABET = 
    " !\"#$%&'()*+,-./0123456789:;<=>?@" +
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`" +
    "abcdefghijklmnopqrstuvwxyz{|}";

String encodeBase94(byte[] data) {
    // Similar to Base91 but with different alphabet
    // Uses variable-length encoding
}
```

## File Contents Map

| File | Key | Contents |
|------|-----|----------|
| .0.jpg | utdid | Device unique identifier |
| .1.jpg | session | Authentication token |
| .2.jpg | install | Install timestamp |
| .3.jpg | device | Device model/brand |
| .4.jpg | android_id | Android ID hash |
| .5.jpg | display | Screen metrics |
| .6.jpg | network | Network info |
| .7.jpg | os | Android version |
| .8.jpg | app | App version |
| .9.jpg | sensors | Sensor fingerprint |
| .10.jpg | adid | Advertising ID |
| .11.jpg | locale | Language/timezone |
| .12.jpg | master | Combined fingerprint |

## Cross-App Tracking

All Alibaba apps share the same UTDID by:
1. Writing to Settings.System (requires WRITE_SETTINGS permission)
2. Reading from shared external storage (.gs directories)
3. Using common SharedPreferences if running as same user

This allows Taobao, Alipay, AliExpress, UC Browser etc. to track the same device across all apps.
