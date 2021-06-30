# WusaBypassUAC
This exploit is similar to how https://github.com/L3cr0f/DccwBypassUAC works as it abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. Here we abuse that method in [Windows Update Standalone Installer(wusa.exe)](https://support.microsoft.com/en-us/topic/description-of-the-windows-update-standalone-installer-in-windows-799ba3df-ec7e-b05e-ee13-1cdae8f23b19) by its call to comctl32.dll 
- Tested on Windows 10 20H2, hopefully will work on Windows 8.1 as well.
- Supports "x86" and "x64" architectures.

# DISCLAIMER
**I do not take any responsibility if someone uses the exploit provided in this repository to perform illegal activities.**

## 1. Process Vulnerability

### 1.1. Checking Manifest
"Windows Update Standalone Installer" or "wusa.exe" is one of the processes which have autoElevate attribute as true in its manifest. This is why it can run as Administrator without UAC Prompts.

This is proven by [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck):

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/sigcheck.png">

### 1.2. Capturing execution by Process Monitor

By filtering execution of wusa.exe caught by [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon), we found that wusa.exe tried to check by [IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) if location **wusa.exe.Local** is available in C:\Windows\System32\, whereas in 32bit it will be checked under C:\Windows\SysWOW64\ as shown below:

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/procmon.PNG">

However, wusa.exe is trying to look for a DLL called [comctl32.dll](https://docs.microsoft.com/en-us/windows/win32/controls/common-controls-intro) similar to how dccw.exe looks for GdiPlus.dll. 
Since it doesn't contain the DLL, wusa.exe looks under WinSxS for a folder with the structure:
<p>[arch]_microsoft.windows.common-controls_[sequencial_code]_[windows_version]_none_[sequencial_number]</p>

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/winsxsdir.PNG">
However, there are two folders from where comctl32.dll can be loaded by wusa.exe.

This can be exploited by a 32bit process when it copies a Malicious DLL to one of these locations and invokes wusa.exe which will launch its target program and children with high integrity.

### 1.3. Vulnerability Verification

Since we know that a mode of vulnerability is possible, we can verify it by creating the **"wusa.exe.Local"** folder and under that the first WinSxS folder wusa.exe loads comctl32.dll from. On doing that and on capturing the execution of wusa.exe in Procmon, we get the following results:

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/wusaerror.png">

As we expected, wusa.exe throws an error as it cannot find comctl32.dll under any of those folders we created. This proves that the vulnerability exists in wusa.exe.

## 2. Developing an exploit
On developing one, we followed the same steps as [Exploit-Development](https://github.com/L3cr0f/DccwBypassUAC#13-exploit-development) till [Interoperability](https://github.com/L3cr0f/DccwBypassUAC#133-interoperability).

### 2.1. The Malicious DLL
Just like dccw.exe, wusa.exe depends on some functions from comctl32.dll that we need to create or forward to the original DLL. Without implementing or forwarding the execution of these functions to the original DLL, wusa.exe will fail to launch with an error that it can't find those functions in the DLL.

#### 2.1.1. Porting Exports To Original DLL
Ofcourse we can use the tool [ExportsToC++](https://github.com/michaellandi/exportstoc) to port all exports from comctl32.dll to C++ by **pragma**, this resolves the issue of defining them.

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/exportsToC.PNG">

The reason we are using **"C:\Windows\System32\"** is because this path does not change in Windows unlike the WinSxS folders.

#### 2.1.2. Checking Imports
All available functions are resolved and saved as a cpp source. However, we only need to forward the functions wusa.exe needs, not all from comctl32.dll. To check which all functions are imported by wusa.exe, we can use the MSVC tool called [DUMPBIN](https://docs.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=msvc-160) which lists out several information about a binary file. We can use the following command to list out the imports from wusa.exe:
```shell
dumpbin.exe /IMPORTS C:\Windows\System32\wusa.exe
```

DUMPBIN shows the following imports of wusa.exe from comctl32.dll:

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/dumpbinwusa.PNG">

#### 2.1.3 Passing by Ordinal

By this, we can figure out that wusa.exe only imports 2 functions from comctl32.dll and that we have to provide exports for those functions only.
<p>However, one of the functions it imports are by ordinal 344 and not by its name. ExportsToC++ only generates exports by names and some with [NONAME].</p>
But this can easily be dealt with, by the following export:

```c++
#pragma comment (linker, "/export:#344=c:/windows/system32/comctl32.#344,@344,NONAME")
```

### 2.2. Avoiding Detection by Antimalware and Users
This process of copying the malicious DLL, doing other functions leaves a trace to the system and even the user may come upon what we are doing if something goes wrong. For this reason, all the temporary files created during the process are removed after the exploit is successful.

## 3. Final Execution
After the exploit is successful, we can execute any malicious code, open programs or whatever written within our malicious DLL as Administrator without UAC Prompts.

