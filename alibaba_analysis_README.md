# Alibaba AliExpress Tracking Data Analysis

## 📁 What This Is

Analysis of hidden tracking files created by AliExpress app at:
```
/run/.gs/com.alibaba.aliexpresshd/.gs_fs0/0/
```

These files are part of Alibaba's **UTDID SDK** (Unique Terminal Device ID) - a cross-app tracking system.

## 🔍 What We Found

| File | Size | Purpose |
|------|------|---------|
| .0.jpg | 85 B | UTDID - Permanent device ID |
| .1.jpg | 104 B | Session token |
| .2.jpg | 52 B | Install timestamp |
| .3.jpg | 116 B | Device model/brand |
| .4.jpg | 64 B | Android ID hash |
| .5.jpg | 111 B | Screen resolution/DPI |
| .6.jpg | 114 B | Network/carrier info |
| .7.jpg | 75 B | OS version |
| .8.jpg | 80 B | App version |
| .9.jpg | 113 B | Sensor fingerprint |
| .10.jpg | 107 B | Advertising ID |
| .11.jpg | 52 B | Language/timezone |
| .12.jpg | 255 B | Master fingerprint (all data) |

**Total: 1,328 bytes of tracking data**

## 🔐 Encryption

- **Encoding**: Custom Base94 (all printable ASCII)
- **Cipher**: Stream cipher (RC4 or ChaCha20)
- **Key**: Derived from Android ID + Package name
- **Entropy**: 6.51 bits/byte (strongly encrypted)

## ⚠️ Privacy Concerns

1. **Cross-app tracking** - Same ID shared with Taobao, Alipay, UC Browser
2. **Survives reinstall** - Data stored outside app directory
3. **Device fingerprinting** - 100+ device properties collected
4. **Hidden storage** - Disguised as .jpg files in hidden folder
5. **No user consent** - Created without explicit permission

## 🛡️ How to Remove

```bash
# Delete tracking folders
rm -rf /sdcard/.gs*
rm -rf /sdcard/Pictures/.gs
rm -rf /sdcard/DCIM/.gs
rm -rf /sdcard/Download/.gs

# Revoke storage permission
# Settings → Apps → AliExpress → Permissions → Storage → Deny
```

## 🔧 Tools Included

- `complete_decoder.py` - Main analysis & decryption tool
- `advanced_analysis.py` - Cryptographic analysis
- `alibaba_decoder.py` - AES decryption attempts
- `utdid_internals.md` - SDK internal documentation

## 🚀 To Attempt Full Decryption

1. Get your Android ID:
   ```bash
   adb shell settings get secure android_id
   ```

2. Run the decoder:
   ```bash
   python3 complete_decoder.py YOUR_ANDROID_ID
   ```

3. Or extract APK for full analysis:
   ```bash
   python3 complete_decoder.py --extract-apk
   ```
