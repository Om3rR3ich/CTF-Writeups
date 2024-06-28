# Hooked on a Flag
## Challenge Description

**Category**: Mobile

**Description**: The flag is waiting for you to find it. Can you hook your way to victory?

![challenge_description](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/2bd3c3f6-2361-4d4f-865e-8eeddc0de733)

An android application file (apk) is provided, of what seems like a simple storage interface for flags.
It's possible to both add a new flag and store a new one. The goal of the challenge was not stated in the description,
but it did hint towards function hooking. 

## Overview & Decompilation
As usual with apk's, I decompiled it using JADX.
The manifest file reveals 3 main activities the app uses:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="30" android:compileSdkVersionCodename="11" package="com.example.addflag" platformBuildVersionCode="30" platformBuildVersionName="11">
    <uses-sdk android:minSdkVersion="16" android:targetSdkVersion="30"/>
    <application android:theme="@style/Theme.AddFlag" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
        <activity android:name="com.example.addflag.DisplayFlagsActivity"/>
        <activity android:name="com.example.addflag.addFlag"/>
        <activity android:name="com.example.addflag.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```
MainActivity was rather dull, so I'll skip it in this overview. However, addFlag proved to be more intersting, especially the `K` method:
```java
    /* renamed from: K */
    public final void mo7052K(String flag) {
        C1073d dbHelper = C1073d.m5737f(this);
        SQLiteDatabase db = dbHelper.getWritableDatabase(C1074e.m5744b().mo6017d(this));
        ContentValues values = new ContentValues();
        values.put("owner", "user");
        String encryptedFlag = dbHelper.mo6011e(flag);
        values.put("flag", encryptedFlag);
        values.put("length", Integer.valueOf(encryptedFlag.length()));
        values.put("tag", dbHelper.mo6012g());
        db.insert("FLAGS", (String) null, values);
    }
```

It seems that the application encrypts the flag provided by the user before inserting it into the database,
along with its length and a mysterious 'tag' value.

Also note that the flags are always put by the `owner` user, which heavily hints towards the existence of an admin account of some sort.
The lack of any authentication system in the app led me to believe that the real flag resides (encrypted) in the database, and
owned by an admin user.

## Finding & Decrypting the DB
Now that we have a better understanding of the app's inner-workings and the challenge's (assumed) goal, we can delve further into the details.
It's clear that the DBMS is SQLite, and confirmed by noticing that C1073d (`dbHelper`'s type) extends `net.sqlcipher.database.SQLiteOpenHelper`.
An examination of this class's constructor reveals the name of the database:
```java
    public C1073d(Context context) {
        super(context, "flags.ty", null, 1);
        SQLiteDatabase.loadLibs(context);
        this.f3759c = context;
        f3758b = context.getDatabasePath("flags.ty").getPath();
    }
```
So the DB's file name is `flags.ty` (which is a rather unusual file extension for a database file).
But how can we get this file?

Well, remember that an apk file is a simple zip archive in disguise. 7z (or any other tool) does the trick, and flags.ty can be extracted
from the `assets` directory.

Nevertheless, one barrier still stands between us and discovering the app's arcane secrets - the database is encrypted!
Let's take a step back and review how data gets inserted into the database in `addFlag` (if you're not sure how to decrypt the database, I invite you to re-read the code snippet),
especially at this line, in which `db` is initialized:
```java
        SQLiteDatabase db = dbHelper.getWritableDatabase(C1074e.m5744b().mo6017d(this));
```

As you probably know, before accessing an encrypted database (for either writing or reading), it needs to be decrypted.

This means that the password is hiding somewhere in the process of creating a usable `SQLiteDatabase` object.
Decompiling `getWritableDatabse` we find:
```java
    public synchronized SQLiteDatabase getWritableDatabase(String password) {
        return getWritableDatabase(password == null ? null : password.toCharArray());
    }
```

Thus, discovering the password is laughably simple - just check the parameter passed to this function.

This kind of task is often done by intercepting the function, but before jumping eagerly into Frida, you might ask yourselves:

What the hell is `C1074e.m5744b().mo6017d(this)` even doing?

For all you know, the password can be hardcoded into the return value of `mo6017d`.
In this case, that's not very far from the truth:
```java
    /* renamed from: d */
    public String mo6017d(Context context) {
        return context.getSharedPreferences("com.example.addflag_preferences", 0).getString("string_2", "Default Value");
    }
```

The database password is taken from the shared preferences! (string_2)
An easy to locate, unencrypted, file. Great.

Anyway, you can find this app's shared preferences file at
`/data/data/com.example.addflag/shared_prefs`

Using ADB:
`# cat com.example.addflag_preferences.xml`

Which results in:
```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="string_2">1l0v3ch0c0lA7e</string>
    <string name="string_1">Fh@S/xW]y$?q</string>
    <string name="string_0">8[V3@eL521#@R2XNX3?4vygXw4$2Jr</string>
</map>
```

So the database's password is: `1l0v3ch0c0lA7e`.

Armed with this password, the database can be read.
One record that does not belong to `user` is found:

![encrypted_flag](https://github.com/Om3rR3ich/CTF-Writeups/assets/88339137/32eace15-1914-42b2-8689-4c01df4d7116)

## Decrypting the Flag
All that is left is to decrypt the flag, so let's see what exactly is hiding under the hood of `dbHelper.mo6011e`.

The result is rather disappointing:
```java
    /* renamed from: e */
    public String mo6011e(String flag) {
        byte[] cipherFlag = new byte[(((flag.length() + 16) / 16) * 16)];
        byte[] tag = new byte[16];
        utility.m6842a().encrypt(flag, flag.length(), C1074e.m5744b().mo6016c(this.f3759c), C1074e.m5744b().mo6015a(this.f3759c), cipherFlag, tag);
        this.f3760d = Base64.encodeToString(tag, 0);
        return Base64.encodeToString(cipherFlag, 0);
    }
```

Basic encoding aside, the encryption mechanism hides behind `utility.m6842a().encrypt`, which isn't present in the decompiled Java source code!

Rather than panicking, remember the Java Native Interface (JNI) - a framework that enables to incorporate native (C/C++) code into a Java application.

Indeed, we find the smoking gun in the definition of the `utility` class:
```Java
public class utility {

    /* renamed from: a */
    public static utility f4517a = null;

    public native int decrypt(byte[] bArr, int i, String str, String str2, byte[] bArr2, byte[] bArr3);

    public native int encrypt(String str, int i, String str2, String str3, byte[] bArr, byte[] bArr2);
```

Considering this information, we expect to find a shared object (`libUtility.so`) packed inside the apk file.
There are two possible approaches to a final solution - 
1. Use Frida to call the `decrypt` function with the encrypted flag and tag (probably the intended solution considering the challenge's name)
2. Reverse engineer `libUtility.so` to understand what `encrypt` is doing, and use this knowledge to decrypt the flag (which is what I did)

As per the JNI naming convention, `encrypt` will probably be called `Java_{PACKAGE_NAME}_utility_encrypt` (unless obfuscated).
Decompiling that (I used IDA Pro), we get:

```c
__int64 __fastcall Java_com_example_addflag_utility_encrypt(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        unsigned int a4,
        __int64 a5,
        __int64 a6,
        __int64 a7,
        __int64 a8)
{
  __int64 v10; // r15
  const char *v12; // rbp
  int v13; // ecx
  void *v14; // rax
  __int64 v15; // rsi
  __int64 v16; // rax
  __int64 v17; // r15
  __int64 v18; // rax
  char *v19; // r13
  int v20; // ebp
  int v21; // ebx
  unsigned int v22; // ebx
  void *v23; // r15
  int v25; // [rsp+4h] [rbp-A4h] BYREF
  __int64 v26; // [rsp+8h] [rbp-A0h]
  __int64 v27; // [rsp+10h] [rbp-98h]
  __int64 v28; // [rsp+18h] [rbp-90h]
  void *ptr; // [rsp+20h] [rbp-88h]
  const char *v30; // [rsp+28h] [rbp-80h]
  __int64 v31; // [rsp+30h] [rbp-78h]
  __int64 v32; // [rsp+38h] [rbp-70h]
  __int128 v33; // [rsp+40h] [rbp-68h] BYREF
  char v34[88]; // [rsp+50h] [rbp-58h] BYREF

  v10 = a4;
  v27 = (*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a3, 0LL);
  v12 = (const char *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a5, 0LL);
  v28 = (*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)a1 + 1352LL))(a1, a6, 0LL);
  v26 = v10;
  v13 = v10 + 31;
  if ( (int)v10 + 16 >= 0 )
    v13 = v10 + 16;
  v14 = calloc(1uLL, (int)(v13 & 0xFFFFFFF0));
  if ( v14 )
  {
    ptr = v14;
    v32 = a3;
    v33 = 0LL;
    v15 = strlen(v12);
    sub_1D70((__int64)v12, v15, (__int64)v34);
    v16 = EVP_CIPHER_CTX_new();
    if ( !v16 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
    v17 = v16;
    v18 = EVP_aes_256_gcm();
    if ( (unsigned int)EVP_EncryptInit_ex(v17, v18, 0LL, v34, v28) != 1 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
    v30 = v12;
    v31 = a5;
    v19 = (char *)ptr;
    if ( (unsigned int)EVP_EncryptUpdate(v17, ptr, &v25, v27, v26) != 1 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
    v20 = v25;
    if ( (unsigned int)EVP_EncryptFinal_ex(v17, &v19[v25], &v25) != 1 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
    v26 = a6;
    v21 = v25;
    if ( (unsigned int)EVP_CIPHER_CTX_ctrl(v17, 16LL, 16LL, &v33) != 1 )
    {
      ERR_print_errors_fp(stderr);
      abort();
    }
    v22 = v20 + v21;
    EVP_CIPHER_CTX_free(v17);
    v23 = ptr;
    (*(void (__fastcall **)(__int64, __int64, _QWORD, _QWORD, void *))(*(_QWORD *)a1 + 1664LL))(a1, a7, 0LL, v22, ptr);
    (*(void (__fastcall **)(__int64, __int64, _QWORD, __int64, __int128 *))(*(_QWORD *)a1 + 1664LL))(
      a1,
      a8,
      0LL,
      16LL,
      &v33);
    (*(void (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 1360LL))(a1, v32, v27);
    (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, v31, v30);
    (*(void (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 1360LL))(a1, v26, v28);
    free(v23);
  }
  else
  {
    (*(void (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 1360LL))(a1, a3, v27);
    (*(void (__fastcall **)(__int64, __int64, const char *))(*(_QWORD *)a1 + 1360LL))(a1, a5, v12);
    (*(void (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)a1 + 1360LL))(a1, a6, v28);
    return (unsigned int)-1;
  }
  return v22;
}
```

It's clear that AES-GCM 256 bit is used. 
This time, it's not hardcoded, but passed as a parameter to the `encrypt` function (AES is symmetric so the encryption key is also the decryption key).
Fortunately, the library uses the well known and documented OpenSSL functions (rather than a custom implementation), so the parameters and conventions are readily avilable:
```c
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key, const unsigned char *iv);
```

So the key and IV are the last two parameters, in our case they're `v34` and `v28` respectively.
With a little bit of analysis (combined with the previous analysis of the apk) we find that key and IV that are passed
by the application are the other two strings we found previously in the shared preferences.

While the IV (`string_1`) is 12 bytes as expected, the supposed key is only 30 bytes (as opposed to the required size of 32 bytes).
Occam's razor may tempt us to just try random paddings until something works, but all such attempts are (in this case) futile.

If you bother re-checking the `encrypt` method inside `libUtility.so`, you can see that the key parameter is being preprocessed by the `sub_1D70` function
(check line 50: ```sub_1D70((__int64)v12, v15, (__int64)v34);```).
Hmmm, what is that for?

```c
__int64 __fastcall sub_1D70(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // rax
  __int64 v5; // rbx
  __int64 v6; // rax
  __int64 v8[5]; // [rsp+0h] [rbp-28h] BYREF

  v8[0] = 32LL;
  v4 = EVP_MD_CTX_new(a1);
  if ( !v4 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  v5 = v4;
  v6 = EVP_sha256();
  if ( (unsigned int)EVP_DigestInit_ex(v5, v6, 0LL) != 1 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  if ( (unsigned int)EVP_DigestUpdate(v5, a1, a2) != 1 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  if ( (unsigned int)EVP_DigestFinal_ex(v5, a3, v8) != 1 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  return EVP_MD_CTX_free(v5);
}
```

This function appears to calculate the sha256 of the key (and use that as a key instead).
Hence the real key isn't `8[V3@eL521#@R2XNX3?4vygXw4$2Jr`, but `sha256("8[V3@eL521#@R2XNX3?4vygXw4$2Jr")`.

This makes sense, because the output of sha256 is always 256 bits = 32 bytes.

Based on this information, I put together a quick Python script to decrypt the flag:

```python
from Crypto.Cipher import AES
from hashlib import sha256
import base64

key = b'8[V3@eL521#@R2XNX3?4vygXw4$2Jr'
key = sha256(key).digest()

iv = b'Fh@S/xW]y$?q'

ciphertext = base64.b64decode(b'l5wMg7HQCuXMk3Dkf3GDlLX52+VM0bZcDCQIZjyVJlKZ3hh9LMIUY13zzlgimU3IAAAAAAAAAAAAAAAAAAAAAA==')

aes = AES.new(key, AES.MODE_GCM, iv)
print(aes.decrypt(ciphertext))
```

Running it results in:
`b'BSidesTLV2024{4ndr01d_dc0mp1l3_4nd_h00k_15_fun!}\x14\x05\xbb\xdbyy\xa5\xc3WT\x19C\xd5\x9a7E'`


## Addendum
It was cool to see that an android challenge was included in BsidesTLV.
Nevertheless, it was little disappointing that it was the only one, especially considering its difficulty.
Hopefully there will be more challenging tasks next year!
