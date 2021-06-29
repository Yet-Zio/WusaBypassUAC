# WusaBypassUAC
This exploit is similar to how https://github.com/L3cr0f/DccwBypassUAC works as it abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. Here we abuse that method in [Windows Update Standalone Installer(wusa.exe)](https://support.microsoft.com/en-us/topic/description-of-the-windows-update-standalone-installer-in-windows-799ba3df-ec7e-b05e-ee13-1cdae8f23b19) by its call to comctl32.dll 
- Tested on Windows 10 20H2, hopefully will work on Windows 8.1 as well.
- Supports "x86" and "x64" architectures.

## 1. Process Vulnerability

### 1.1 Checking Manifest
"Windows Update Standalone Installer" or "wusa.exe" is one of the processes which have autoElevate attribute as true in its manifest. This is why it can run as Administrator without UAC Prompts.

This is proven by [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck):

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/sigcheck.png">

### 1.2 Capturing execution by Process Monitor

By filtering execution of wusa.exe caught by [Procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon), we found that wusa.exe tried to check by [IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) if location **wusa.exe.Local** is available in C:\Windows\System32\, whereas in 32bit it will be checked under C:\Windows\SysWOW64\ as shown below:

<img src="https://github.com/Yet-Zio/WusaBypassUAC/blob/main/snaps/procmon.PNG">

However, wusa.exe is trying to look for a DLL called [comctl32.dll](https://docs.microsoft.com/en-us/windows/win32/controls/common-controls-intro) similar to how dccw.exe looks for GdiPlus.dll. 
Since it doesn't contain the DLL, wusa.exe looks under WinSxS for a folder with the structure:
<p>[arch]_microsoft.windows.common-controls_[sequencial_code]_[windows_version]_none_[sequencial_number]</p>

