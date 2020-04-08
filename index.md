![hot](https://xakep.ru/wp-content/uploads/2016/11/FCKUAC-h.jpg)




# System Requirements

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

