# ZyAFS-OSX: Advanced Forensic Shredder for MacOS

**ZyAFS-OSX** is an advanced forensic shredder designed for MacOS, offering a secure and permanent method to delete sensitive files and directories from your system. The program implements various data shredding algorithms, ensuring that data is effectively overwritten and made unrecoverable.

## Key Features:

1. **Secure File Shredding:** ZyAFS-OSX provides a reliable way to securely shred individual files, ensuring that the data in the file is overwritten multiple times, making it nearly impossible to recover the original information.
2. **Directory Shredding:** In addition to shredding individual files, ZyAFS-OSX supports shredding entire directories, making it convenient to securely delete a collection of files and folders.
3. **Strong Cryptographic Algorithms:** The program employs strong cryptographic algorithms to overwrite data, guaranteeing the highest level of data security.
4. **Optimized for SSDs:** ZyAFS-OSX supports the TRIM command, which enhances performance and ensures secure data deletion on Solid State Drives (SSDs).

## Installation:
To use ZyAFS-OSX, you must have the OpenSSL library installed on your system. If you don't have it installed, follow these steps to install it:

**1. Open Terminal**

**2. Install Homebrew (if not installed):**

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

**3. Install OpenSSL using Homebrew:**


```brew install openssl```

## Usage:

After installing the OpenSSL library, compile the program using the following command:

```gcc -o shredder shredder.c -lcrypto```

Once the compilation is successful, you can use the program to securely shred files and directories. The program accepts two command-line arguments:

**filename/directory:** The path to the file or directory you want to shred.

**algorithm:** The algorithm to use for shredding. Supported algorithms are **nullbytes**, **randomdata**, **dod5220**, **gutmann**, and **polymorphic**.

**Example usage:**
```
./shredder file.txt polymorphic
./shredder folder_to_shred gutmann
```

## Supported Algorithms:

ZyAFS-OSX supports the following shredding algorithms:

1. **Null Bytes:** Overwrites the file with null bytes, effectively making it unrecoverable.
2. **Random Data:** Fills the file with random data, ensuring data security.
3. **DoD 5220.22-M:** Uses the US Department of Defense 3-pass standard for data sanitization, providing a high level of data security.
4. **Gutmann (35-pass):** Utilizes Gutmann's 35-pass algorithm for extreme data overwrite, providing an extremely high level of data security.
5. **Polymorphic 12-pass:** Implements a polymorphic algorithm with a strong cryptographic stream cipher and dynamic initialization vectors (IVs) for enhanced data security.

**Note:** Before using ZyAFS-OSX, ensure you have the necessary permissions to shred the specified files and directories, as shredding is a permanent action and data cannot be recovered once overwritten.
