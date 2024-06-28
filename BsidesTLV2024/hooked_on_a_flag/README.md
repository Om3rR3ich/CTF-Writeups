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


