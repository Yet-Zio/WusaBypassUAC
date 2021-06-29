# WusaBypassUAC
This exploit is similar to how https://github.com/L3cr0f/DccwBypassUAC works as it abuses the way "WinSxS" is managed by "dccw.exe" by means of a derivative Leo's Davidson "Bypass UAC" method so as to obtain an administrator shell without prompting for consent. Here we abuse that method in Windows Update Standalone Installer(wusa.exe) by its call to comctl32.dll 
- Tested on Windows 10 20H2, hopefully will work on Windows 8.1 as well.
- Supports "x86" and "x64" architectures.
