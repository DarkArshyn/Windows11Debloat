# Windows 11 Debloat Script
## General Information
This script can be used to debloat Windows 11 (but should work on Windows 10). It removes bloatware and configures some parts of Windows.
However, you can easily disable some parts of the script if you don't want to remove or add some fonctionnalities.

This script uses PowerShell and DISM.

Since the script is written in PowerShell, you need to modify the default script execution policy. To do this, run a PowerShell terminal as an administrator, then enter the command `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false`. This policy will allow only the local user to execute scripts on the machine. Once done, you can launch the script without any issues.

<ins>Edit (08/05/24) :</ins> I've created a simple graphical interface for this script that allows choosing which element to delete (view in release section). The program has been compiled with **[PS2EXE](https://github.com/MScholtes/PS2EXE)**

> [!TIP]
> You're free to use or modify the script as you want (AGPL Licence). Feedback are also appreciated, it can help me to improve the script and fix bugs.

> [!NOTE]
> By default, the time configuration is noted like this : dd-MM-yyyy and hour set to 24h (European time format).

## What's set ?

### Apps deleted

All bloatware are removed from Windows. Only those applications remain :

- All System Apps
- AVCEncoderVideoExtension
- DesktopAppInstaller
- DolbyAudioExtensions
- HEIFImageExtension
- HEVCVideoExtension
- MPEG2VideoExtension
- Paint
- RawImageExtension
- ScreenSketch
- SecHealthUI (Windows Defender)
- StorePurchaseApp
- VCLibs
- VP9VideoExtensions
- WebMediaExtensions
- WebpImageExtension
- WindowsCalculator
- WindowsNotepad
- WindowsStore
- WindowsTerminal

Edge and OneDrive are also removed.

> [!NOTE]
> An application can be added or removed from the exclusion list (look at "**Windows bloatware removal**" section).

### Telemetry

With registry manipulation, telemetry is disabled. You can see it in the "**Registry : Privacy**" section.

### Performances

With registry manipulation, performances are boosted. Components like background applications or SmartScreen are disabled. You can see it in the "**Registry : Performances**" section.

### Customization

With registry manipulation, I have customize some parts of Windows like restore old context menu or set Taskbar to the left. You can see it in the "**Registry : Customization**" section.

> [!NOTE]
> Currently, it's not possible to automatically unpin default pinned apps from the Start Menu for the local user. However, the registry key applies to newly created users, and therefore, they won't encounter the issue.

> [!NOTE]
> To restore the old context menu for all users, I created a scheduled task that runs every time a session is opened and creates the appropriate registry key if it doesn't exist. The method of change the Default user registry setting didn't work in this case, so I had to resort to this approach.

## What's next ?

It's currently planned to include all necessary modifications in future Windows updates. When Microsoft rolls out an update that introduces an unwanted feature (e.g. advertising), I'll include the appropriate changes.

## Another possibility

If you want to deploy a clean and lightweight Windows, I recommend checking out my other script created **[here](https://github.com/DarkArshyn/Windows11Lite)**, which I used as inspiration to create this one.
