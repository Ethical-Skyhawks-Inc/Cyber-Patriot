::********************************************************************
::	Program:	Windows Security Script
::	filename:	winSecure.bat
::	Aouthor:	omegablue
::____________________________________________________________________
SETLOCAL
:: Turn off screen output when running script
@echo off
:: Clear Screen
cls

:: Check for ADMIN access by trying to run a NET SESSION
:: To run as admin type "runas /user:Administrator winSecure.bat"
echo Checking permissions...
net session >> nul 2>&1
if %errorLevel% == 0 (echo.) else (echo PERMISSIONS ERROR: Need admin access & goto :eof)

echo Starting Scripts...

:: < Configure Report > ::
set tStamp=%random%
set sR=%cd%\securityReport%tStamp%.txt
echo Security Report Details >> %sR%
echo Scan Date: %DATE% >> %sR%
echo Scan Time: %TIME% >> %sR%

:: < Manage Accounts> ::
echo. & echo Hardening Accounts...
echo. >> %sR%
echo ------------------------------------------------------ >> %sR%
echo Users: >> %sR%
echo ------------------------------------------------------ >> %sR%
net user > %cd%\users.txt
MORE /E +4 %cd%\users.txt > users2.txt
findstr /R /V "The command completed successfully." %cd%\users2.txt >> %sR%
del %cd%\users.txt & del %cd%\users2.txt

:: Disable Administrator
net user Administrator /active:no >> nul 2>&1
:: Diable Guest
net user Guest /active:no >> nul 2>&1
:: Rename "Guest" accounts to notGuest
wmic useraccount where name='Guest' rename notGuest >> nul 2>&1

:: < Password Policies > ::
echo. & echo Hardening Password Policies...
net accounts /MINPWLEN:10 >> nul 2>&1
net accounts /MINPWAGE:7 >> nul 2>&1
net accounts /MAXPWAGE:30 >> nul 2>&1
net accounts /UNIQUEPW:3 >> nul 2>&1
net accounts /LOCKOUTDURATION:30 >> nul 2>&1
net accounts /LOCKOUTTHRESHOLD:5 >> nul 2>&1
net accounts /LOCKOUTOBSERVATION:30 >> nul 2>&1

:: < StartUp > ::
echo. & echo Audting StartUp Processes...
echo. >> %sR%
echo ------------------------------------------------------ >> %sR%
echo StartUp Processes: >> %sR%
echo ------------------------------------------------------ >> %sR%
wmic startup list instance > %cd%\suProcs.txt
MORE /E +1 suProcs.txt >> %sR%
echo. >> %sR%
echo If any look suspect use 'wmic startup list full' to examine further >> %sR%
del %cd%\suProcs.txt

:: < Features > ::
echo. & echo Disabling Windows Features...
:: Uncomment to disable the feature 
::dism /online /disable-feature /featurename:IIS-WebServerRole >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-WebServer >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-CommonHttpFeatures >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HttpErrors >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HttpRedirect >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ApplicationDevelopment >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-NetFxExtensibility >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HttpLogging >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-LoggingLibraries >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-RequestMonitor >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HttpTracing >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-Security >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-URLAuthorization >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-RequestFiltering >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-IPSecurity >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-Performance >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-WebServerManagementTools >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ManagementScriptingTools >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-Metabase >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HostableWebCore >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-StaticContent >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-DefaultDocument >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-DirectoryBrowsing >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-WebDAV >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-WebSockets >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ApplicationInit >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ASPNET >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ASPNET45 >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ASP >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-CGI >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ISAPIExtensions >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ISAPIFilter >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ServerSideIncludes >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-CustomLogging >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-BasicAuthentication >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-HttpCompressionStatic >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ManagementConsole >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-ManagementService >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-WMICompatibility >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-LegacyScripts >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-LegacySnapIn >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-FTPServer >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-FTPSvc >> nul 2>&1
::dism /online /disable-feature /featurename:IIS-FTPExtensibility >> nul 2>&1
::dism /online /disable-feature /featurename:TFTP >> nul 2>&1
::dism /online /disable-feature /featurename:TelnetClient >> nul 2>&1
::dism /online /disable-feature /featurename:TelnetServer >> nul 2>&1

:: < Services > ::
echo. & echo Audting Running Services...
echo. >> %sR%
echo ------------------------------------------------------ >> %sR%
echo Services: >> %sR%
echo ------------------------------------------------------ >> %sR%
net start >> %sR%
:: Stop List
echo. & echo Stopping Harmful Services...
for %%S in (tapisrv,bthserv,mcx2svc,remoteregistry,seclogon,telnet,tlntsvr,p2pimsvc,simptcp,fax,msftpsvc,nettcpportsharing,iphlpsvc,lfsvc,bthhfsrv,irmon,sharedaccess,xblauthmanager,xblgamesave,xboxnetapisvc) do (
	sc config %%S start= disabled >> nul 2>&1
	sc stop %%S >> nul 2>&1
)
:: Auto List
echo. & echo Configuring Other Services...
for %%S in (eventlog,mpssvc) do (
	sc config %%S start= auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)
:: Auto-Delayed
for %%S in (windefend,sppsvc,wuauserv) do (
	sc config %%S start= delayed-auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)
:: Manual List
for %%S in (wersvc,wecsvc) do (
	sc config %%S start= demand >> nul 2>&1
)

:: < Windows Updates > ::
:: add [key] /V [valueName] /T [DataType] /D [dataValue] /F=force w/out prompt
echo. & echo Enabling Windows to Auto-Update...
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V AUOptions /T REG_DWORD /D 4 /F >> nul 2>&1
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ElevateNonAdmins /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V IncludeRecommendedUpdates /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ScheduledInstallTime /T REG_DWORD /D 22 /F >> nul 2>&1

:: < Remote Access > ::
echo. & echo Disabling Remote Access...
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V fDenyTSConnections /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V UserAuthentication /T REG_DWORD /D 0 /F >> nul 2>&1
reg ADD "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F >> nul 2>&1
reg ADD "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F >> nul 2>&1
reg ADD "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F >> nul 2>&1
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F >> nul 2>&1

:: < Firewall > ::
echo. & echo Igniting your Firewall...
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no >NUL
netsh advfirewall firewall set rule name="Telnet Server" new enable=no >NUL
netsh advfirewall firewall set rule name="netcat" new enable=no >NUL
netsh advfirewall set allprofiles state on >> nul 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >> nul 2>&1

:: < Flush DNS > ::
ipconfig /flushdns >> nul 2>&1
attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
echo > C:\Windows\System32\drivers\etc\hosts

:: < Media Files & Malware > ::
echo. & echo Checking system for media files...
:: Acquire list of all users' directories
dir /S /B "C:\Users\" > %APPDATA%\dirList.txt
:: Filter out Microsoft and AppData directories; speeds up the process
find /I /V "Microsoft" %APPDATA%\dirList.txt | find /I /V "AppData" %APPDATA%\dirList.txt > %APPDATA%\filteredDirList.txt	
echo. >> %sR%
echo ------------------------------------------------------ >> %sR%
echo Media File Locations: >> %sR%
echo ------------------------------------------------------ >> %sR%
:: Add extensions to "mediaTypes"
:: MEDIA TYPE ENDINGS: AIF,M3U,M4A,MID,MP3,MPA,RA,WAV,WMA,3G2,3GP,ASF,ASX,AVI,FLV,M4V,MOV,MP4,MPG,RM,SRT,SWF,VOB,WMV,BMP,GIF,JPG,PNG,PSD,TIF,YUV,GAM,SAV,TORRENT,WEBM,FLV,OG
set mediaTypes= AVI WMA MOV
for %%X in (%mediaTypes%) do (
	findstr /I "\.%%X" %APPDATA%\filteredDirList.txt >> %sR%
)
echo. >> %sR%
echo ------------------------------------------------------ >> %sR%
echo Possible Malware File Locations: >> %sR%
echo ------------------------------------------------------ >> %sR%
:: Add malicious software to "malware"
set malware= "nmap" keylogger Armitage Caine Metasploit Shellter
for %%Y in (%malware%) do (
	findstr /I "%%Y" %APPDATA%\filteredDirList.txt >> %sR%
)	
del %APPDATA%\dirList.txt & del %APPDATA%\filteredDirList.txt

:: < Auditing > ::
:: Track Everything!
auditpol /set /category:* /success:enable >> nul 2>&1
auditpol /set /category:* /failure:enable >> nul 2>&1

:: < More Hardening Options > ::
:: Explorer see all!
reg ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V Hidden /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F >> nul 2>&1
reg ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V ShowSuperHidden /T REG_DWORD /D 1 /F >> nul 2>&1
:: NetLogon Hardening
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V MaximumPasswordAge /T REG_DWORD /D 15 /F >> nul 2>&1
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V DisablePasswordChange /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V RequireStrongKey /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V RequireSignOrSeal /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V SignSecureChannel /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /V SealSecureChannel /T REG_DWORD /D 1 /F >> nul 2>&1
:: Disable Floppy Drives
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /V AllocateCDRoms /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /V AllocateFloppies /T REG_DWORD /D 1 /F >> nul 2>&1
:: Windows Options for the uber paranoid
reg ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoDriveTypeAutorun /T REG_DWORD /D 255 /F >> nul 2>&1
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /V NoAutorun /T REG_DWORD /D 1 /F >> nul 2>&1 
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V DontDisplayLastUsername /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V UndockWithoutLogon /T REG_DWORD /D 0 /F >> nul 2>&1
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V DisableCAD /T REG_DWORD /D 0 /F >> nul 2>&1
:: Why would you want anyone/anything saving your password?
reg ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /V DisablePasswordCaching /T REG_DWORD /D 1 /F >> nul 2>&1
:: Enable IE Phishing Filters and other options; although deleting IE should be the only one
reg ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /V EnabledV8 /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /V EnabledV9 /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /V DoNotTrack /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Download" /V RunInvalidSignatures /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /V LOCALMACHINE_CD_UNLOCK /T REG_DWORD /D 1 /T >> nul 2>&1
:: Removing your own dump is prudent
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /V CrashDumpEnabled /T REG_DWORD /D 0 /F >> nul 2>&1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /V Machine /T REG_MULTI_SZ /D "" /F >> nul 2>&1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /V Machine /T REG_MULTI_SZ /D "" /F >> nul 2>&1
:: I'll tell you start
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /V AutoRun /T REG_DWORD /D 1 /F >> nul 2>&1
:: You have not won an IPad; these warnings should help
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V WarnonBadCertRecving /T REG_DWORD /D /1 /F >> nul 2>&1
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V WarnOnPostRedirect /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V WarnonZoneCrossing /T REG_DWORD /D 1 /F >> nul 2>&1
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /V DisablePasswordCaching /T REG_DWORD /D 1 /F >> nul 2>&1
:: Restart Explorer
taskkill /IM explorer.exe /F >> nul 2>&1
start explorer.exe

:: System Scan
set /P choice=System Integrity Scan[Y/N]?
if /I "%choice%" EQU "Y" (
	echo on
	Sfc.exe /scannow
	@echo off
)

:end
echo. & echo Finalizing...
echo. & echo Security Scan completed on %DATE% at %TIME%
echo Security Report generated at %sR%
