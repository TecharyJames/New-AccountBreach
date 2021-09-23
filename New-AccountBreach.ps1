###############################
### James Tarran // Techary ###
###############################

# Elevates to admin
param([switch]$Elevated)

function Test-Admin {
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated)
    {
        # tried to elevate, did not work, aborting
    }
    else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
}

exit



function Get-NewPassword {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][Switch]$SkipUpperCase,
        [Parameter(Mandatory=$false)][Switch]$SkipLowerCase,
        [Parameter(Mandatory=$false)][Switch]$SkipNumbers,
        [Parameter(Mandatory=$false)][Switch]$SkipSymbols,
        [Parameter(Mandatory=$false)][Int]$PasswordLength = 16,
        [Parameter(Mandatory=$false)][Int]$NumberOfPasswords = 1,
        [Parameter(Mandatory=$false)][String]$PasswordsFilePath
    )
    
    begin {
        if($SkipUpperCase.IsPresent -and $SkipLowerCase.IsPresent -and $SkipNumbers.IsPresent -and $SkipSymbols.IsPresent){
            Write-Error "You may not skip all four types of characters at the same time, try again..."
            Exit
        }

        $CharArray = New-Object System.Collections.ArrayList
        $ValidatePass = New-Object System.Collections.ArrayList

        $LowerLetters = New-Object System.Collections.ArrayList; 97..122 | % {$LowerLetters.Add([Char]$_)} | Out-Null
        $UpperLetters = New-Object System.Collections.ArrayList; 65..90 | % {$UpperLetters.Add([Char]$_)} | Out-Null
        $Numbers = New-Object System.Collections.ArrayList; 0..9 | % {$Numbers.Add($_.ToString())} | Out-Null
        $Symbols = New-Object System.Collections.ArrayList; 33..47 | % {$Symbols.Add([Char]$_)} | Out-Null

        if(!$SkipNumbers.IsPresent){$CharArray.Add($Numbers) | Out-Null; $ValidatePass.Add(1) | Out-Null}
        if(!$SkipLowerCase.IsPresent){$CharArray.Add($LowerLetters) | Out-Null; $ValidatePass.Add(2) | Out-Null}
        if(!$SkipUpperCase.IsPresent){$CharArray.Add($UpperLetters) | Out-Null; $ValidatePass.Add(3) | Out-Null}
        if(!$SkipSymbols.IsPresent){$CharArray.Add($Symbols) | Out-Null; $ValidatePass.Add(4) | Out-Null}

        $WorkingSet = $CharArray | % {$_}
    }
    
    process {
        if($PasswordsFilePath -and !(Test-Path $PasswordsFilePath)){
            New-Item $PasswordsFilePath -ItemType File
        }

        for($i = 0; $i -le $NumberOfPasswords; $i++){
            $Password = New-Object System.Collections.ArrayList
            for($y = 0; $y -le $PasswordLength; $y++){
                $Character = $WorkingSet | Get-Random
                $Password.Add($Character) | Out-Null
            }

            Switch ($ValidatePass){
                1 {if(!($Password -match '\d')){$PassNotValid = $true}}
                2 {if(!($Password -cmatch "[a-z]")){$PassNotValid = $true}}
                3 {if(!($Password -cmatch "[A-Z]")){$PassNotValid = $true}}
                4 {
                    $Password | % {if($Symbols -contains $_){$ContainSymbol = $true}}
                    if($ContainSymbol -eq $false){$PassNotValid = $true}
                    $ContainSymbol = $false
                }
            }
            if($PassNotValid -eq $true){$i = $i - 1; $PassNotValid = $false; continue}else {
                $Password = $Password -join ""
                if($PasswordsFilePath){Add-Content -Path $PasswordsFilePath -Value $Password}else{Return $Password}
            }
        }
    }
    
    end {
        Write-Verbose -Message "Finishing function"
    }
}

function print-TecharyLogo {
    
    $logo = "
      _______        _                      
     |__   __|      | |                     
        | | ___  ___| |__   __ _ _ __ _   _ 
        | |/ _ \/ __| '_ \ / _`` | '__| | | |
        | |  __/ (__| | | | (_| | |  | |_| |
        |_|\___|\___|_| |_|\__,_|_|   \__, |
                                       __/ |
                                      |___/ 
"

    write-host -ForegroundColor Green $logo

}


function connect-365 {

    function invoke-mfaConnection {

        Connect-ExchangeOnline

        import-module MSOnline

        import-module ExchangeOnlineManagement
        
        import-module AzureAD

        Connect-MsolService

        }

    function Get-ExchangeOnlineManagement {

        Set-PSRepository -Name "PSgallery" -InstallationPolicy Trusted

        Install-Module -Name ExchangeOnlineManagement

        }

    Function Get-MSonline {

        Set-PSRepository -Name "PSgallery" -InstallationPolicy Trusted

        Install-Module MSOnline

        }

    function Get-AzureAD {

        Set-PSRepository -Name "PSgallery" -InstallationPolicy Trusted

        install-module AzureADPreview

    }


    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) 
    {
        write-host " "
        write-host "Exchange online Management exists, updating..."
        update-module -name ExchangeOnlineManagement
    } 
    else 
    {
        Write-host "Exchange Online Management module does not exist. Please ensure powershell is running as admin. Attempting to download..."
        Get-ExchangeOnlineManagement
    }


    if (Get-Module -ListAvailable -Name MSOnline) 
    {
        write-host "MSOnline exists, updating..."
        update-module -name MSOnline
    } 
    else 
    {
        Write-host "MSOnline module does not exist. Please ensure powershell is running as admin. Attempting to download..."
        Get-MSOnline
    }

    if (Get-Module -ListAvailable -Name AzureAD) 
    {
        write-host "AzureAD exists, removing...."
        remove-module -name AzureAD | Out-Null
        uninstall-module -name AzureAD | Out-Null
        Remove-Item -path "C:\Program Files\WindowsPowerShell\modules\AzureAD" -recurse -force | Out-Null
        Remove-Item -path "C:\Program Files (x86)\WindowsPowerShell\modules\AzureAD" -recurse -force | Out-Null
    } 
    else 
    {
    
        Get-AzureAD

    }

    invoke-mfaConnection

}

function get-ADConnectStatus {

    $MSOL = (Get-MsolDirSyncFeatures).enabled

    if ($msol -contains "True") 
        {
            
            $DomainRole = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole

            if ($DomainRole -match '4|5')
                {
                    
                    start-LocalAccountBreach

                }
            
            else 
                {
            
                    write-host -ForegroundColor Red "This 365 tenant has ADConnect. Please run this script on a domain controller."

                    start-sleep 5
                
                }

        
        } 
    
    else
        {

            start-CloudAccountBreach

        }

}

function get-upn {

    $script:upn = Read-Host "Enter the UPN of the breached account"

    if (Get-MsolUser -UserPrincipalName $script:upn -ErrorAction SilentlyContinue) 
    {
        Write-host "User found..."
        $global:upn
    }

    else 
    {
        write-host "User not found, try again" 
        get-upn
        
    }

}

function Set-NewCloudPassword {

    $Script:NewCloudPassword = Get-NewPassword -PasswordLength 12 -NumberOfPasswords 1

    $SecureCloudPassword = SecurePassword = ConvertTo-SecureString $script:NewLocalPassword -AsPlainText -force

    Set-MsolUserPassword -UserPrincipalName $script:upn -NewPassword $SecureCloudPassword
  
}

function set-NewLocalPassword {

    $Script:NewLocalPassword = Get-NewPassword -PasswordLength 12 -NumberOfPasswords 1

    $SecureLocalPassword = SecurePassword = ConvertTo-SecureString $script:NewLocalPassword -AsPlainText -force

    get-aduser -filter "userPrincipalName -eq '$script:upn'" | Set-ADAccountPassword -newpassword $SecureLocalPassword

}

function revoke-365Access {

    Revoke-AzureADUserAllRefreshToken -ObjectId $script:upn

}

function remove-RestrictedUser {

    Remove-BlockedSenderAddress -SenderAddress $script:upn

}

function get-ADLogs {

    (Get-AzureADAuditDirectoryLogs -filter "userprincipalName eq '$script:upn'").location | export-csv "$env:userprofile\LoggedInLocations.csv"

}

function disable-maliciousRules {

    $RuleID = (get-inboxrule -mailbox $script:upn).RuleIdentity

    foreach ($rule in $RuleID)
        {
            disable-inboxrule -mailbox $script:upn -identity $rule
        }

    $RuleNames = get-inboxrule -mailbox $script:upn | select name

    Write-Host "The following mailbox rules have been disabled:"

    $RuleNames

}

function start-CloudAccountBreach {

    Start-Transcript -path "$env:userprofile\AccountBreach.txt"

    print-TecharyLogo

    get-upn

    Set-NewCloudPassword

    revoke-365Access

    remove-RestrictedUser

    get-ADLogs

    disable-maliciousRules

    write-host "The password has been reset to $script:NewCloudPassword"

    write-host "`nThe login locations for $script:upn have been saved to $env:userprofile\LoggedInLocations.csv. 
                `nA transcript of this script has been saved to $env:userprofile\AccountBreach.txt. 
                `nPlease now call the user, if you haven't already, and run through getting outlook set back up.
                `nOnce outlook has been setup, please then run through oulook rules with the user, as ALL rules have been disabled. Some may actually be in use."

}

function start-LocalAccountBreach {

    Start-Transcript -path "$env:userprofile\AccountBreach.txt"

    print-TecharyLogo

    get-upn

    set-NewLocalPassword

    revoke-365Access

    remove-RestrictedUser

    get-ADLogs

    disable-maliciousRules

    write-host "The password has been reset to $script:newlocalpassword, please perform a directory sync in ADConnect.
                `nThe login locations for $script:upn have been saved to $env:userprofile\LoggedInLocations.csv.
                `nA transcript of this script has been saved to $env:userProfile\AccountBreach.txt.
                `nPlease now call the user, if you haven't already, and run through setting them back up with logging back into their PC with their new password, re-setting up 365 apps, and ensuring the VPN credentials are cleared if required.
                `nOnce outlook is setup, please then run through outlook rules with the user, as ALL rules have been disabled. Some may actually be in use."

}

connect-365

get-ADConnectStatus