Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$objForm = New-Object System.Windows.Forms.Form 
$objForm.Text = "Win 11 Debloat GUI"
$objForm.ClientSize = '795,350'
$objForm.StartPosition = "CenterScreen"
$objForm.BackColor = "White"
$objForm.KeyPreview = $True
$objForm.Topmost = $True
$objform.MaximizeBox = $False
$objForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog

$Version = New-Object System.Windows.Forms.Label
$Version.Text = "Version 1.1.1"
$Version.AutoSize = $true
$Version.Location = New-Object System.Drawing.Size(710,304)
$objForm.Controls.Add($Version)

#############################
#                           #
#     Bloatware Section     #
#                           #
#############################

#Primary bloatware removal
$BloatwareGroupBox = New-Object System.Windows.Forms.GroupBox
$BloatwareGroupBox.Location = New-Object System.Drawing.Size(10,18)
$BloatwareGroupBox.Size = New-Object System.Drawing.Size(260,50)
$BloatwareGroupBox.Text = "Do you want to remove all APPX apps ?"

#Bloatware removal Yes/No
$BloatwareYesButton = New-Object System.Windows.Forms.RadioButton
$BloatwareYesButton.text = "Yes"
$BloatwareYesButton.AutoSize = $true
$BloatwareYesButton.Checked  = $true
$BloatwareYesButton.Location = New-Object System.Drawing.Size(10,20) 
$BloatwareGroupBox.Controls.Add($BloatwareYesButton)

#Bloatware removal Yes/No
$BloatwareNoButton = New-Object System.Windows.Forms.RadioButton
$BloatwareNoButton.text = "No"
$BloatwareNoButton.AutoSize = $true
$BloatwareNoButton.Checked  = $false
$BloatwareNoButton.Location = New-Object System.Drawing.Size(115,20) 
$BloatwareGroupBox.Controls.Add($BloatwareNoButton)

#Tooltip creation
$BloatwareInfo = New-Object System.Windows.Forms.ToolTip
$BloatwareInfo.InitialDelay = 100     
$BloatwareInfo.ReshowDelay = 100 
$BloatwareInfo.SetToolTip($BloatwareGroupBox, "This settings removes Windows APPX applications (e.g., Cortana, Mail, Xbox...)")

$BloatwareGroupBox.add_MouseEnter({

    #Capture mouse position
    $MousePosition = $BloatwareGroupBox.PointToClient([System.Windows.Forms.Control]::MousePosition)

})


$objForm.Controls.Add($BloatwareGroupBox)

########################################
#                                      #
#    Additionnal Bloatware Section     #
#                                      #
########################################

#Additionnal bloatware removal
$AdditionnalBloatwareGroupBox = New-Object System.Windows.Forms.GroupBox
$AdditionnalBloatwareGroupBox.Location = New-Object System.Drawing.Size(10,68)
$AdditionnalBloatwareGroupBox.Size = New-Object System.Drawing.Size(260,50)
$AdditionnalBloatwareGroupBox.Text = "Choose what you want to debloat :"

#Edge Box
$EdgeButton = New-Object System.Windows.Forms.CheckBox
$EdgeButton.text = "Edge"
$EdgeButton.Checked  = $true
$EdgeButton.Location = New-Object System.Drawing.Size(10,20) 
$AdditionnalBloatwareGroupBox.Controls.Add($EdgeButton)

#OneDrive Box
$OneDriveButton = New-Object System.Windows.Forms.CheckBox
$OneDriveButton.text = "OneDrive"
$OneDriveButton.Checked  = $true
$OneDriveButton.Location = New-Object System.Drawing.Size(115,20) 
$AdditionnalBloatwareGroupBox.Controls.Add($OneDriveButton)

#Tooltip creation
$AdditionnalBloatwareInfo = New-Object System.Windows.Forms.ToolTip
$AdditionnalBloatwareInfo.InitialDelay = 100     
$AdditionnalBloatwareInfo.ReshowDelay = 100 
$AdditionnalBloatwareInfo.SetToolTip($AdditionnalBloatwareGroupBox, "This settings removes Edge and OneDrive")

$AdditionnalBloatwareGroupBox.add_MouseEnter({

    #Capture mouse position
    $MousePosition = $AdditionnalBloatwareGroupBox.PointToClient([System.Windows.Forms.Control]::MousePosition)

})

$objForm.Controls.Add($AdditionnalBloatwareGroupBox)

############################
#                          #
#     Registry Section     #
#                          #
############################

#Registry tweaking
$RegistryGroupBox = New-Object System.Windows.Forms.GroupBox
$RegistryGroupBox.Location = New-Object System.Drawing.Size(10,120)
$RegistryGroupBox.Size = New-Object System.Drawing.Size(260,70)
$RegistryGroupBox.Text = "Choose what registry tweaking you want :"

#Privacy Box
$PrivacyButton = New-Object System.Windows.Forms.CheckBox
$PrivacyButton.text = "Privacy"
$PrivacyButton.Checked  = $true
$PrivacyButton.Location = New-Object System.Drawing.Size(10,20) 
$RegistryGroupBox.Controls.Add($PrivacyButton)

#Performance Box
$PerformanceButton = New-Object System.Windows.Forms.CheckBox
$PerformanceButton.text = "Performance"
$PerformanceButton.Checked  = $true
$PerformanceButton.Location = New-Object System.Drawing.Size(115,20) 
$RegistryGroupBox.Controls.Add($PerformanceButton)

#Customization Box
$CustomizationButton = New-Object System.Windows.Forms.CheckBox
$CustomizationButton.text = "Customization"
$CustomizationButton.Checked  = $true
$CustomizationButton.Location = New-Object System.Drawing.Size(10,40) 
$RegistryGroupBox.Controls.Add($CustomizationButton)

#Tooltip creation
$RegistryInfo = New-Object System.Windows.Forms.ToolTip
$RegistryInfo.InitialDelay = 100     
$RegistryInfo.ReshowDelay = 100 
$RegistryInfo.SetToolTip($RegistryGroupBox, "This settings makes changes to the registry")

$RegistryGroupBox.add_MouseEnter({

    #Capture mouse position
    $MousePosition = $RegistryGroupBox.PointToClient([System.Windows.Forms.Control]::MousePosition)

})

$objForm.Controls.Add($RegistryGroupBox)

################################
#                              #
#     Context Menu Section     #
#                              #
################################

#Old Context Menu for All Users
$ContextMenuGroupBox = New-Object System.Windows.Forms.GroupBox
$ContextMenuGroupBox.Location = New-Object System.Drawing.Size(10,193)
$ContextMenuGroupBox.Size = New-Object System.Drawing.Size(260,50)
$ContextMenuGroupBox.Text = "Restore Old Context Menu for All Users ?"

#Context Menu Yes/No
$ContextYesButton = New-Object System.Windows.Forms.RadioButton
$ContextYesButton.text = "Yes"
$ContextYesButton.AutoSize = $true
$ContextYesButton.Checked  = $true
$ContextYesButton.Location = New-Object System.Drawing.Size(10,20)  
$ContextMenuGroupBox.Controls.Add($ContextYesButton)

#Context Menu Yes/No
$ContextNoButton = New-Object System.Windows.Forms.RadioButton
$ContextNoButton.text = "No"
$ContextNoButton.AutoSize = $true
$ContextNoButton.Checked  = $false
$ContextNoButton.Location = New-Object System.Drawing.Size(115,20) 
$ContextMenuGroupBox.Controls.Add($ContextNoButton)

#If Customization uncheck, Context Menu button greyed
$CustomizationButton_OnClick = {
        if ($CustomizationButton.Checked -eq $true)
            {
                $ContextYesButton.Enabled = $true
                $ContextNoButton.Enabled = $true  
            }
        elseif ($CustomizationButton.Checked -eq $false)
            {
                $ContextYesButton.Enabled = $false
                $ContextNoButton.Enabled = $false
            }
    }
$CustomizationButton.Add_Click($CustomizationButton_OnClick)

#Tooltip creation
$ContextInfo = New-Object System.Windows.Forms.ToolTip
$ContextInfo.InitialDelay = 100     
$ContextInfo.ReshowDelay = 100 
$ContextInfo.SetToolTip($ContextMenuGroupBox, "This settings makes changes to the registry")

$ContextMenuGroupBox.add_MouseEnter({

    #Capture mouse position
    $MousePosition = $ContextMenuGroupBox.PointToClient([System.Windows.Forms.Control]::MousePosition)

})

$objForm.Controls.Add($ContextMenuGroupBox)

###################################
#                                 #
#     Windows Version Section     #
#                                 #
###################################

#Windows Version
$WindowsVersionGroupBox = New-Object System.Windows.Forms.GroupBox
$WindowsVersionGroupBox.Location = New-Object System.Drawing.Size(10,243)
$WindowsVersionGroupBox.Size = New-Object System.Drawing.Size(260,50)
$WindowsVersionGroupBox.Text = "What's your Windows version"

#Windows Version Text
$WindowsText = New-Object System.Windows.Forms.Label
$WindowsText.Location = New-Object System.Drawing.Size(10,20)
$WindowsText.AutoSize = $true
$WindowsText.Text = (Get-WmiObject -class Win32_OperatingSystem).Caption
$WindowsVersionGroupBox.Controls.Add($WindowsText)

$objForm.Controls.Add($WindowsVersionGroupBox)

##################################
#                                #
#     Output Console Section     #
#                                #
##################################

#Output Console
$OutputConsoleGroupBox = New-Object System.Windows.Forms.GroupBox
$OutputConsoleGroupBox.Location = New-Object System.Drawing.Size(280,18)
$OutputConsoleGroupBox.Size = New-Object System.Drawing.Size(505,275)
$OutputConsoleGroupBox.Text = "Output Console"

$ConsoleOutput = New-Object System.Windows.Forms.RichTextBox
$ConsoleOutput.BackColor = [System.Drawing.Color]::DarkBlue
$ConsoleOutput.ForeColor = [System.Drawing.Color]::White
$ConsoleOutput.Font = New-Object System.Drawing.Font("Consolas", 10)
$ConsoleOutput.Multiline = $true
$ConsoleOutput.ScrollBars = "Vertical"
$ConsoleOutput.Location = New-Object System.Drawing.Size(10,20)
$ConsoleOutput.Size = New-Object System.Drawing.Size(485,245)
$ConsoleOutput.Anchor = "Left","Top","Right","Bottom"
$ConsoleOutput.ReadOnly = $true
$ConsoleOutput.BorderStyle = "Fixed3d"
$OutputConsoleGroupBox.Controls.Add($ConsoleOutput)

$objForm.Controls.Add($OutputConsoleGroupBox)

############################
#                          #
#     Dark Mode Button     #
#                          #
############################

#Dark Mode
$DarkModeButton = New-Object System.Windows.Forms.CheckBox
$DarkModeButton.text = "Dark Mode"
$DarkModeButton.Checked  = $false
$DarkModeButton.AutoSize = $true
$DarkModeButton.Location = New-Object System.Drawing.Size(15,304) 
$objForm.Controls.Add($DarkModeButton) 

$DarkModeButtonButton_OnClick = {
        if ($DarkModeButton.Checked -eq $true)
            {
                $objForm.BackColor = "#474d58"
                $objForm.ForeColor = "#ffffff"
                $BloatwareGroupBox.ForeColor = "#ffffff"
                $AdditionnalBloatwareGroupBox.ForeColor = "#ffffff"
                $RegistryGroupBox.ForeColor = "#ffffff"
                $ContextMenuGroupBox.ForeColor = "#ffffff"
                $WindowsVersionGroupBox.ForeColor = "#ffffff"
                $OutputConsoleGroupBox.ForeColor = "#ffffff"
            }
        elseif ($DarkModeButton.Checked -eq $false)
            {
                $objForm.BackColor = "#ffffff"
                $objForm.ForeColor = "#000000"
                $BloatwareGroupBox.ForeColor = "#000000"
                $AdditionnalBloatwareGroupBox.ForeColor = "#000000"
                $RegistryGroupBox.ForeColor = "#000000"
                $ContextMenuGroupBox.ForeColor = "#000000"
                $WindowsVersionGroupBox.ForeColor = "#000000"
                $OutputConsoleGroupBox.ForeColor = "#000000"
            }
    }
$DarkModeButton.Add_Click($DarkModeButtonButton_OnClick)

#Tooltip creation
$DarkModeText = New-Object System.Windows.Forms.ToolTip
$DarkModeText.InitialDelay = 100     
$DarkModeText.ReshowDelay = 100 
$DarkModeText.SetToolTip($DarkModeButton, "You can change the application style to light or dark mode")

$DarkModeButton.add_MouseEnter({

    #Capture mouse position
    $MousePosition = $DarkModeButton.PointToClient([System.Windows.Forms.Control]::MousePosition)

})

######################
#                    #
#     Run Button     #
#                    #
######################

#Run Button
$RunButton = New-Object System.Windows.Forms.Button
$RunButton.Location = New-Object System.Drawing.Size(100,300)
$RunButton.AutoSize = $true
$RunButton.Text = "Run"
$objForm.Controls.Add($RunButton)

##############################################
##############################################

$RunButton.Add_Click({

            ########################
            #                      #
            #     Color Output     #
            #                      #
            ########################

            $yellowBrush = [System.Drawing.Color]::Yellow
            $greenBrush = [System.Drawing.Color]::Green
            $redBrush = [System.Drawing.Color]::Red

            #############################
            #                           #
            #     Bloatware Section     #
            #                           #
            #############################

            If($BloatwareYesButton.Checked -eq $true){

                $ConsoleOutput.SelectionColor = $yellowBrush
                $ConsoleOutput.AppendText("Removing bloatware, please wait...`r`n")
                $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
    
                Try{

                    $ExcludeApp = "1527c705-839a-4832-9118-54d4Bd6a0c89","c5e2524a-ea46-4f67-841f-6a9465d9d515","E2A4F912-2574-4A75-9BB0-0D023378592B","F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE","Microsoft.AAD.BrokerPlugin","Microsoft.AccountsControl","Microsoft.MicrosoftEdge.Stable","Microsoft.AsyncTextService","Microsoft.AV1VideoExtension","Microsoft.AVCEncoderVideoExtension","Microsoft.BioEnrollment","Microsoft.CredDialogHost","Microsoft.MicrosoftEdgeDevToolsClient","Microsoft.UI.Xaml.CBS","Microsoft.Win32WebViewHost","Microsoft.Windows.Apprep.ChxApp","Microsoft.Windows.AssignedAccessLockApp","Microsoft.Windows.CallingShellApp","Microsoft.Windows.CapturePicker","Microsoft.Windows.CloudExperienceHost","Microsoft.Windows.ContentDeliveryManager","Microsoft.DolbyAudioExtensions","Microsoft.Windows.NarratorQuickStart","Microsoft.Windows.OOBENetworkCaptivePortal","Microsoft.Windows.OOBENetworkConnectionFlow","Microsoft.Windows.PeopleExperienceHost","Microsoft.Windows.ParentalControls","Microsoft.Windows.PinningConfirmationDialog","Microsoft.Windows.PrintQueueActionCenter","Microsoft.Windows.SecureAssessmentBrowser","Microsoft.Windows.StartMenuExperienceHost","Microsoft.Windows.XGpuEjectDialog","Microsoft.WindowsAppRuntime.CBS","Microsoft.XboxGameCallableUI","MicrosoftWindows.Client.Core","MicrosoftWindows.Client.FileExp","MicrosoftWindows.UndockedDevKit","NcsiUwpApp","Windows.CBSPreview","windows.immersivecontrolpanel","Windows.PrintDialog","Microsoft.UI.Xaml.2.4","Microsoft.VCLibs.140.00","Microsoft.NET.Native.Runtime.2.2","Microsoft.NET.Native.Framework.2.2","Microsoft.DesktopAppInstaller","Microsoft.HEIFImageExtension","Microsoft.HEVCVideoExtension","Microsoft.MPEG2VideoExtension","Microsoft.RawImageExtension","Microsoft.ScreenSketch","Microsoft.StorePurchaseApp","Microsoft.VP9VideoExtensions","Microsoft.WebMediaExtensions","Microsoft.WebpImageExtension","Microsoft.WindowsCalculator","Microsoft.WindowsNotepad","Microsoft.WindowsTerminal","Microsoft.SecHealthUI","Microsoft.VCLibs.140.00.UWPDesktop","Microsoft.WindowsAppRuntime.1.5","Microsoft.UI.Xaml.2.8","Microsoft.VCLibs.140.00","Microsoft.NET.Native.Runtime.2.2","Microsoft.NET.Native.Framework.2.2","Microsoft.Paint","Microsoft.WindowsStore","Microsoft.UI.Xaml.2.7","MicrosoftWindows.Client.LKG","Microsoft.WindowsAppRuntime.CBS","MicrosoftWindows.Client.Core","Microsoft.ECApp","Microsoft.LockApp","Microsoft.Windows.ShellExperienceHost","MicrosoftWindows.Client.CBS","Microsoft.Windows.AugLoop.CBS","MicrosoftWindows.Client.AIX","MicrosoftWindows.Client.Core","MicrosoftWindows.Client.FileExp","MicrosoftWindows.Client.OOBE","MicrosoftWindows.Client.Photon"

                    $GetAppExclude = Get-AppxPackage -AllUsers | Select Name | Where Name -notin $ExcludeApp
                    $GetAppExcludeV2 = $GetAppExclude.Name -notlike 'Microsoft.WindowsAppRuntime*' -notlike 'Microsoft.LanguageExperiencePack*' -notlike 'Microsoft.ApplicationCompatibilityEnhancements' -notlike 'Microsoft.Services.Store.Engagement'

                    ForEach ($App in $GetAppExcludeV2){
                        $ConsoleOutput.AppendText("Removing $App...`r`n")
                        $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                        $ConsoleOutput.ScrollToCaret()
                        $progressPreference = 'SilentlyContinue'
                        Get-AppxPackage -AllUsers $App | Remove-AppPackage
                    }

                    $ConsoleOutput.SelectionColor = $yellowBrush
                    $ConsoleOutput.AppendText("Removing bloatware for all users, please wait...`r`n")
                    $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor

                    $DISMExcludeApp = "Microsoft.ApplicationCompatibilityEnhancements","Microsoft.AV1VideoExtension","Microsoft.AVCEncoderVideoExtension","Microsoft.DesktopAppInstaller","Microsoft.DolbyAudioExtensions","Microsoft.HEIFImageExtension","Microsoft.HEVCVideoExtension","Microsoft.MPEG2VideoExtension","Microsoft.MicrosoftEdge.Stable","Microsoft.NET.Native.Framework.2.2","Microsoft.NET.Native.Runtime.2.2","Microsoft.Paint","Microsoft.RawImageExtension","Microsoft.ScreenSketch","Microsoft.SecHealthUI","Microsoft.Services.Store.Engagement","Microsoft.StorePurchaseApp","Microsoft.UI.Xaml.2.7","Microsoft.UI.Xaml.2.8","Microsoft.VCLibs.140.00","Microsoft.VCLibs.140.00.UWPDesktop","Microsoft.VP9VideoExtensions","Microsoft.WebMediaExtensions","Microsoft.WebpImageExtension","Microsoft.WindowsCalculator","Microsoft.WindowsNotepad","Microsoft.WindowsAppRuntime.1.3","Microsoft.WindowsAppRuntime.1.4","Microsoft.WindowsStore","Microsoft.WindowsTerminal"

                    $GetDISMAppExclude = Get-ProvisionedAppxPackage -Online | Select DisplayName,PackageName | Where DisplayName -notin $DISMExcludeApp

                    ForEach ($App in $GetDISMAppExclude.PackageName){
                        $ConsoleOutput.AppendText("Removing $App using DISM...`r`n")
                        $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                        $ConsoleOutput.ScrollToCaret()
                        dism /Online /Remove-ProvisionedAppxPackage /PackageName:$App
                    }

                    $ConsoleOutput.SelectionColor = $greenBrush
                    $ConsoleOutput.AppendText("Bloatware removal completed`r`n")
                    $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                    $ConsoleOutput.ScrollToCaret()

                }
                Catch{

                    $ConsoleOutput.SelectionColor = $redBrush
                    $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                    $ConsoleOutput.ScrollToCaret()
                    $ConsoleOutput.AppendText("Bloatware removal failed. An error has been detected : $($_.Exception.Message).`r`n")
                    $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor

                }
            }

            ########################################
            #                                      #
            #    Additionnal Bloatware Section     #
            #                                      #
            ########################################

            If($EdgeButton.Checked -eq $true){
            
            $ConsoleOutput.SelectionColor = $yellowBrush
            $ConsoleOutput.AppendText("Removing Edge, please wait...`r`n")
            $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
            $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
            $ConsoleOutput.ScrollToCaret()
                
                Try{

                    $ChildItem = Get-ChildItem ${env:ProgramFiles(x86)}\Microsoft\Edge\Application setup.exe -Recurse -Force
                    $EdgeVersionDirectory = $ChildItem.DirectoryName
                    $EdgeDirectory = $EdgeVersionDirectory|ForEach {$_ +  "\setup.exe"}

                    ps msedge | Stop-Process -Force

                    #If multiple version exists
                    ForEach($EdgeVersion in $EdgeDirectory){
                        Start-process $EdgeVersion "-uninstall --force-uninstall --system-level --delete-profile"
                    }

                    
                    Remove-Item -Force -Recurse ${env:ProgramFiles(x86)}\Microsoft\Edge

                    $GetAllEdgeApp = Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -like '*microsoftedge*' } | Select-Object -ExpandProperty PackageFullName
                    $GetUsernameSID = Get-LocalUser -Name $env:USERNAME | Select Name,SID
                    ForEach ($EdgeApp in $GetAllEdgeApp) {
                        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$($GetUsernameSID.SID.Value)\$($EdgeApp)" /f
                        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\$($EdgeApp)" /f
                        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\$($EdgeApp)" /f
                        $progressPreference = 'SilentlyContinue'
                        Remove-AppxPackage -Package $EdgeApp -ErrorAction SilentlyContinue
                        Remove-AppxPackage -Package $EdgeApp -AllUsers -ErrorAction SilentlyContinue
                    }

                    If(Test-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\*edge*.lnk"){
                        Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\*edge*.lnk"
                    }
                    If(Test-Path "$env:PUBLIC\Desktop\*edge*.lnk"){
                        Remove-Item "$env:PUBLIC\Desktop\*edge*.lnk"
                    }

                    Stop-Process -ProcessName explorer -Force

                    Start-Sleep 5

                    $ConsoleOutput.SelectionColor = $greenBrush
                    $ConsoleOutput.AppendText("Edge removal completed`r`n")
                    $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                    $ConsoleOutput.ScrollToCaret()
                }
                Catch{

                    $ConsoleOutput.SelectionColor = $redBrush
                    $ConsoleOutput.AppendText("Edge removal failed. An error has been detected : $($_.Exception.Message).`r`n")
                    $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
                    $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                    $ConsoleOutput.ScrollToCaret()

                }

            }

            If($OneDriveButton.Checked -eq $true){

            $ConsoleOutput.SelectionColor = $yellowBrush
            $ConsoleOutput.AppendText("Removing OneDrive, please wait...`r`n")
            $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
            $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
            $ConsoleOutput.ScrollToCaret()
                
                Try{

                    #Stop OneDrive process
                    ps onedrive | Stop-Process -Force

                    If (Test-Path -Path "$env:windir\SysWOW64\OneDriveSetup.exe" -PathType Leaf) {
                        Start-process "$env:windir\SysWOW64\OneDriveSetup.exe" "/uninstall"
                    }
                    Else {
                        Start-process "$env:windir\System32\OneDriveSetup.exe" "/uninstall"
                    }
    
                    #Find local administrator
                    $GetAdminSID = Get-LocalGroup -SID "S-1-5-32-544"
                    $Admin = $GetAdminSID.Name

                    #Assigning rights to the appdata folder and deleting it
                    $OneDriveLocation = "$env:localappdata\Microsoft\OneDrive"
                    $ACL = Get-ACL $OneDriveLocation
                    $Group = New-Object System.Security.Principal.NTAccount("BUILTIN", "$Admin")
                    $ACL.SetOwner($Group)
                    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\$Admin", "FullControl", "Allow")
                    $ACL.SetAccessRule($AccessRule)
                    Set-Acl $OneDriveLocation -AclObject $ACL

                    #Assigning rights to the appdata folder and deleting it
                    If (Test-Path -Path "$env:windir\SysWOW64\OneDriveSetup.exe" -PathType Leaf) {
                        $OneDriveSystemLocation = "$env:windir\SysWOW64\OneDriveSetup.exe"
                    }
                    Else {
                        $OneDriveSystemLocation = "$env:windir\System32\OneDriveSetup.exe"
                    }
                    $ACL = Get-ACL $OneDriveSystemLocation
                    $Group = New-Object System.Security.Principal.NTAccount("BUILTIN", "$Admin")
                    $ACL.SetOwner($Group)
                    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\$Admin", "FullControl", "Allow")
                    $ACL.SetAccessRule($AccessRule)
                    Set-Acl $OneDriveSystemLocation -AclObject $ACL

                    #Block explorer from restart from itself then kill explorer
                    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 0
                    Stop-Process -ProcessName explorer -Force

                    Start-Sleep 5

                    Remove-Item -Path "$env:localappdata\Microsoft\OneDrive" -Recurse -Force

                    If (Test-Path -Path "$env:windir\SysWOW64\OneDriveSetup.exe" -PathType Leaf) {
                        Remove-Item "$env:windir\SysWOW64\OneDriveSetup.exe" -Force
                    }
                    Else {
                        Remove-Item  "$env:windir\System32\OneDriveSetup.exe" -Force
                    }

                    #Restore registry key and restart explorer
                    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 1
                    Start explorer.exe

                    Start-Sleep 5

                    $ConsoleOutput.SelectionColor = $greenBrush
                    $ConsoleOutput.AppendText("OneDrive removal completed`r`n")
                    $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                    $ConsoleOutput.ScrollToCaret()

                }
                Catch{

                    $ConsoleOutput.SelectionColor = $redBrush
                    $ConsoleOutput.AppendText("OneDrive removal failed. An error has been detected : $($_.Exception.Message).`r`n")
                    $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                    $ConsoleOutput.ScrollToCaret()

                }

            }

            #############################################################################
            #   Edit IntegratedServicesRegionPolicySet.json file (Digital Market Act)   #
            #############################################################################

            $ConsoleOutput.SelectionColor = $yellowBrush
            $ConsoleOutput.AppendText("Editing IntegratedServicesRegionPolicySet.json file, please wait...`r`n")
            $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
            $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
            $ConsoleOutput.ScrollToCaret()

            #Find local administrator
            $GetAdminSID = Get-LocalGroup -SID "S-1-5-32-544"
            $Admin = $GetAdminSID.Name

            #Assigning rights to file to edit it
            $ACL = Get-ACL $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $Group = New-Object System.Security.Principal.NTAccount("BUILTIN", "$Admin")
            $ACL.SetOwner($Group)
            Set-Acl -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -AclObject $ACL
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\$Admin", "FullControl", "Allow")
            $ACL.SetAccessRule($AccessRule)
            $ACL | Set-Acl $env:windir\System32\IntegratedServicesRegionPolicySet.json

            #Can uninstall Edge
            $DMAEdgeUninstall = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAEdgeUninstall[7] = $DMAEdgeUninstall[7] -replace 'disabled','enabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAEdgeUninstall

            #Users can disable Web Search from the Start Menu
            $DMAWebSearchDisable = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAWebSearchDisable[17] = $DMAWebSearchDisable[17] -replace 'disabled','enabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAWebSearchDisable

            #Hide files from MS Office MRU recommendation provider
            $DMAOfficeMRU = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAOfficeMRU[157] = $DMAOfficeMRU[157] -replace 'enabled','disabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAOfficeMRU

            #Restrict widget data sharing
            $DMAWidgetDataSharing = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAWidgetDataSharing[207] = $DMAWidgetDataSharing[207] -replace 'disabled','enabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAWidgetDataSharing

            #Restrict data sharing with third-party widgets
            $DMAThirdWidgetDataSharing = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAThirdWidgetDataSharing[217] = $DMAThirdWidgetDataSharing[217] -replace 'disabled','enabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAThirdWidgetDataSharing

            #Disable XBox performance adaptation according to data sharing
            $DMAXboxData = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAXboxData[237] = $DMAXboxData[237] -replace 'enabled','disabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAXboxData

            #Disable Windows Copilot
            $DMAWindowsCopilot = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAWindowsCopilot[257] = $DMAWindowsCopilot[257] -replace 'enabled','disabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAWindowsCopilot

            #Hide website items in Start Menu recommendations
            $DMAStartRecommendations = Get-Content $env:windir\System32\IntegratedServicesRegionPolicySet.json
            $DMAStartRecommendations[297] = $DMAStartRecommendations[297] -replace 'enabled','disabled'
            Set-Content -Path $env:windir\System32\IntegratedServicesRegionPolicySet.json -Value $DMAStartRecommendations

            $ConsoleOutput.SelectionColor = $greenBrush
            $ConsoleOutput.AppendText("IntegratedServicesRegionPolicySet.json file has been edited successfully`r`n")
            $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
            $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
            $ConsoleOutput.ScrollToCaret()

            ############################
            #                          #
            #     Registry Section     #
            #                          #
            ############################

            If($PrivacyButton.Checked -eq $true -or $PerformanceButton.Checked -eq $true -or $CustomizationButton.Checked -eq $true){
                
                $ConsoleOutput.SelectionColor = $yellowBrush
                $ConsoleOutput.AppendText("Tweaking registry, please wait...`r`n")
                $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
                $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                $ConsoleOutput.ScrollToCaret()
                
                #Loading registry keys (System components)
                reg load "HKLM\zNTUSER" $env:HOMEDRIVE\Users\Default\ntuser.dat        #Apply all HKCU keys to all new created users
            }

            If($PrivacyButton.Checked -eq $true){

                #Disable Windows Recall (AI Spyware)
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f
                reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f

                #Disable Windows Copilot
                reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f

                #Disable Windows Welcome Experience
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f

                #Disable Recommended Tips, Shortcuts, New Apps, and more on Start Menu
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d "0" /f

                #Disable Notification Badging for Microsoft Accounts on Start Menu
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d "0" /f

                #Disable ads
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f         #Turn off automatically installing Suggested Apps
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f       #Disable Start Menu Ads or Suggestions
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f                 #Disable Promotional Apps
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f    #Turn off Get fun facts, tips, tricks, and more on your lock screen
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f    #Turn off Showing My People App Suggestions
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f    #Turn off Timeline Suggestions
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f           #Disable Sync Provider Notifications in File Explorer
                reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f                           #Disable Advertising ID
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "0" /f                  #Disable Search Highlights in Start Menu

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "0" /f

                #Disable suggested content in Settings
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f

                #Disable website language access to display relevant content
                reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f

                #Disable files recently used in Quick Access
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f

                #Disable Cortana + Web Explorer (HKCU)
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f

                #Disable Cortana + Web Explorer (HKLM)
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaInAAD" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoSearchInternetInStartMenu" /t REG_DWORD /d "1" /f

                #Disable OneDrive
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMBlockOptIn" /t REG_DWORD /d "1" /f

                #Disable Windows Tips
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f

                #Disable Edge features + telemetry
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "DefaultSearchProviderContextMenuAccessAllowed" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeEnhanceImagesEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeFollowEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "RemoveDesktopShortcutDefault" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HideFirstRunExperience" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f

                #Disable automatically installing Suggested Apps
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '"{\"pinnedList\": [{}]}"' /f

                #Disable Cloud search
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f

                #Disable telemetry
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f                       #Disable telemetry
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f                                 #Disable application telemetry
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "EnableOneSettingsAuditing" /t REG_DWORD /d "0" /f            #Disable OneSettings audit
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f           #Disable sending of device name in Windows diagnostic data
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f          #Disable the commercial data pipeline
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d "0" /f      #Disable desktop analysis processing
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowWUfBCloudProcessing" /t REG_DWORD /d "0" /f             #Disable Cloud WUfB processing
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowUpdateComplianceProcessing" /t REG_DWORD /d "0" /f      #Disable update compliance processing
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableEnterpriseAuthProxy" /t REG_DWORD /d "1" /f           #Disable logged-in user experience and telemetry

                #Disable Steps Recorder
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f

                #Disable Timeline
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f

                #Disable videos and tips in Settings
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f

                #Disable "Look for an app in the Store" + "New Apps Notification"
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d "1" /f

                #Disable Windows Ink Workspace
                reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d "0" /f

                #Disable Windows Chat + Teams
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f
                #reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d "0" /f      #Access denied

                #Disable widgets
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f

                #Start Menu customization
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f                  #Hide recently addes apps
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /t REG_DWORD /d "2" /f                 #Hide most used apps
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d "0" /f        #Disable ads in Start Menu
                #reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f                     #Disable Windows tracking to improve search results. Warning : Breaks search history on third-party tools like StartAllBack

                #Taskbar customization
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoPinningStoreToTaskbar" /t REG_DWORD /d "1" /f                #Unpin Windows Store from Taskbar
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d "1" /f       #Disable Cloud optimized content from Taskbar

                #OOBE Settings
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f                                               #Disable Privacy Experience in OOBE
                reg add "HKLM\SOFTWARE\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f                             #Disable online voice recognition
                reg add "HKLM\SOFTWARE\Software\Microsoft\MdmCommon\SettingValues" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f                                         #Disable computer location
                reg add "HKLM\SOFTWARE\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d "0" /f             #Disable collection of handwriting and keystroke data
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled " /t REG_DWORD /d "0" /f                 #Disable tailored experiences

                #Privacy preferences
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f                       #Disable motion data
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f                 #Disable diagnostic data
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f                   #Disable calendar access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f                  #Disable access to other devices
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f          #Disable file system access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f                       #Disable contacts access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f                           #Disable chat access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f               #Disable documents access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f                #Disable downloads access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f                          #Disable mail access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f                       #Disable location services
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f                      #Disable phone calls
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f               #Disable phone call history
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f                #Disable pictures access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f                         #Disable radios access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f         #Disable user account access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f                  #Disable tasks access
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f                  #Disable videos access
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d "2" /f                                             #Disable access to voice-activated Windows applications
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d "2" /f                                    #Disable access to voice-activated Windows applications when the screen is locked

                #Disable computer location
                reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f 

                #Disable activity history
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f

                #Disable Microsoft Diagnostic Tool (MSDT)
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "100" /f

                #Disable shared experiences
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d "0" /f

                #Disable inventory collection
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f

                #Allow creation of a local account rather than a Microsoft account
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f

                #Remove automatic installation of Outlook and PowerAutomate
                reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /f
                reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /f
                reg delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f
                reg delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f

            }

            If($PerformanceButton.Checked -eq $true){
                
                #Disable background applications
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f

                #Disable SmartScreen (HKCU)
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f

                #Disable SmartScreen (HKLM)
                reg add "HKLM\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" /ve /d "0" /f
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f

                #Disable Hiberboot (Hybrid Start)
                reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

                #Disable power limiting
                reg add "HKLM\SOFTWARE\PCurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

                #Disable Reserved Storage
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f

                #Disable automatic BitLocker encryption when update to 24H2
                reg add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d "1" /f

            }

            If($CustomizationButton.Checked -eq $true){
                

                #RealTimeIsUniversal
                reg add "HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation" /v "RealTimeIsUniversal" /t REG_DWORD /d "1" /f

                #Disable de Xbox DVR
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
                reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f

                #Taskbar tweaking
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f           #Remove Widget
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f           #Remove Teams
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f           #Align taskbar to the left
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2" /f       #Disable News & Interest

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2" /f

                #Enable NumLock on power on
                reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_DWORD /d "2" /f

                #Open File Explorer in "This PC" instead of Quick Access
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f

                #Enable transparency effects
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f

                #Enable accent color on title bars and window borders
                reg add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f

                #Enable "This PC" shortcut on desktop
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f

                #Set desktop icon size to medium
                reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "IconSize" /t REG_DWORD /d "48" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "Mode" /t REG_DWORD /d "1" /f
                reg add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "LogicalViewMode" /t REG_DWORD /d "3" /f

                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "IconSize" /t REG_DWORD /d "48" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "Mode" /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "LogicalViewMode" /t REG_DWORD /d "3" /f

                #The Print Screen button launches Snipping Tool application
                reg add "HKCU\Control Panel\Keyboard" /v "PrintScreenKeyForSnippingEnabled " /t REG_DWORD /d "1" /f
                reg add "HKLM\zNTUSER\Control Panel\Keyboard" /v "PrintScreenKeyForSnippingEnabled " /t REG_DWORD /d "1" /f

                #Hide "Tasks" item on the taskbar by default
                reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
                reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f

                #100% wallpaper quality
                reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "64" /f
                reg add "HKLM\zNTUSER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "64" /f

                #Restore old context menu
                reg add "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /t REG_SZ /d /f

                #Intensify taskbar transparency
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "1" /f

                #Enable startup sound
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "0" /f

                #Remove Cast to device from the context menu
                reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /f

                #Open .msi files in administrator mode
                reg add "HKCR\Msi.Package\shell\runas\command" /t REG_SZ /d 'C:\Windows\System32\msiexec.exe /i "%1" %*' /f

                #Restore Windows Photo Viewer
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer"
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities" /v "ApplicationDescription" /t REG_SZ /d "@%ProgramFiles%\\Windows Photo Viewer\\photoviewer.dll,-3069" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities" /v "ApplicationName" /t REG_SZ /d "@%ProgramFiles%\\Windows Photo Viewer\\photoviewer.dll,-3009" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Gif" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.JFIF" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Png" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
                reg add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".wdp" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f

                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-70"' /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "EditFlags" /t REG_DWORD /d "10000" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-72"' /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3043" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "EditFlags" /t REG_DWORD /d "10000" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-72"' /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3043" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-83"' /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-71"' /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "EditFlags" /t REG_DWORD /d "10000" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-400" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\wmphoto.dll,-72"' /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell"
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3043" /f
                reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

                #####################################
                #   Add additional registry keys    #
                #####################################

                New-Item -Path $env:localappdata\Temp -Name RegDeploy.reg -ItemType File
                Add-Content -Path "$env:localappdata\Temp\RegDeploy.reg" 'Windows Registry Editor Version 5.00

                ; Open .msi files in administrator mode

                [HKEY_CLASSES_ROOT\Msi.Package\shell\runas\command]
                @="C:\\Windows\\System32\\msiexec.exe /i \"%1\" %*"

                ; Open .ps1 files in administrator mode

                [HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\runas\command]
                @="powershell.exe \"-Command\" \"if((Get-ExecutionPolicy ) -ne ''AllSigned'') { Set-ExecutionPolicy -Scope Process Bypass }; & ''%1''\""

                ; Open .vbs files in administrator mode

                [HKEY_CLASSES_ROOT\VBSFile\Shell\runas\command]
                @="C:\\Windows\\System32\\WScript.exe \"%1\" %*"

                ; Installing .cab files

                [HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs]
                @="Install this update"
                "HasLUAShield"=""

                [HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command]
                @="cmd /k dism /online /add-package /packagepath:\"%1\""

                ; Extract .msi files

                [HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\command]
                @="msiexec.exe /a \"%1\" /qb TARGETDIR=\"%1 Contents\""

                ; Integration of photo viewer controls

                [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Tiff\shell\open\command]
                @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
                  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
                  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
                  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
                  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
                  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
                  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
                  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
                  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
                  00,31,00,00,00

                [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\command]
                @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
                  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
                  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
                  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
                  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
                  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
                  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
                  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
                  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
                  00,31,00,00,00


                [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\command]
                @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
                  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
                  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
                  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
                  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
                  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
                  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
                  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
                  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
                  00,31,00,00,00

                [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\command]
                @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
                  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
                  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
                  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
                  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
                  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
                  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
                  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
                  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
                  00,31,00,00,00

                [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command]
                @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
                  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
                  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
                  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
                  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
                  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
                  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
                  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
                  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
                  00,31,00,00,00

                [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command]
                @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
                  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
                  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
                  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
                  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
                  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
                  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
                  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
                  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
                  00,31,00,00,00

                [HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\command]
                @=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
                  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
                  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
                  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
                  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
                  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
                  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
                  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
                  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
                  00,31,00,00,00

                '

                Start-process reg -ArgumentList "import $env:localappdata\Temp\RegDeploy.reg"

            }

            If($PrivacyButton.Checked -eq $true -or $PerformanceButton.Checked -eq $true -or $CustomizationButton.Checked -eq $true){
                #Unloading registry keys (System components)
                reg unload "HKLM\zNTUSER"

                $ConsoleOutput.SelectionColor = $greenBrush
                $ConsoleOutput.AppendText("Registry tweaking completed`r`n")
                $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
                $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
                $ConsoleOutput.ScrollToCaret()

            }


            ################################
            #                              #
            #     Context Menu Section     #
            #                              #
            ################################

            If($CustomizationButton.Checked -eq $true -and $ContextYesButton.Checked -eq $true){
                
                New-Item -Path $env:ProgramData\Microsoft\Windows -Name Explorer -ItemType Directory
                New-Item -Path $env:ProgramData\Microsoft\Windows\Explorer -Name OldContextMenu.cmd -ItemType File
                Add-Content -Path $env:ProgramData\Microsoft\Windows\Explorer\OldContextMenu.cmd '@echo off & setlocal

                reg query HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32 2>NUL || (
                    reg add "HKCU\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /t REG_SZ /d /f
                )

                exit'

                #Find local user and create task
                $GetUsersSID = Get-LocalGroup -SID "S-1-5-32-545"
                $Users = $GetUsersSID.Name

                $taskPath = "\"
                $name = 'Restore Old Context Menu for All Users'
                $action = New-ScheduledTaskAction -Execute "%programdata%\Microsoft\Windows\Explorer\OldContextMenu.cmd" -WorkingDirectory "%programdata%\Microsoft\Windows\Explorer"
                $trigger = New-ScheduledTaskTrigger -AtLogOn
                $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\$Users" -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                $task = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings
                Register-ScheduledTask -TaskName $name -TaskPath $taskPath -InputObject $task

            }

            $ConsoleOutput.SelectionColor = $greenBrush
            $ConsoleOutput.AppendText("Program successfully executed. You can restart the computer for the changes to take effect`r`n")
            $ConsoleOutput.SelectionColor = $ConsoleOutput.ForeColor
            $ConsoleOutput.Select($ConsoleOutput.Text.Length, 0)
            $ConsoleOutput.ScrollToCaret()


})


[void] $objForm.ShowDialog()
