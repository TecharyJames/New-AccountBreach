###############################
### James Tarran // Techary ###
###############################

[CmdletBinding()]
param
    (

        [parameter()][string]$CSV

    )

function Get-NewPassword {

    $SpecialCharacter = @("!","`$","%","^","&","*","'","@","~","#")

    $ieObject = New-Object -ComObject 'InternetExplorer.Application'

    $ieObject.Navigate('https://www.worksighted.com/random-passphrase-generator/')

    while ($ieobject.ReadyState -ne 4)
            {

                    start-sleep -Milliseconds 1

            }

    $currentDocument = $ieObject.Document

    $password = ($currentDocument.IHTMLDocument3_getElementsByTagName("input") | Where-Object {$_.id -eq "txt"}).value
    $password = $password.Split(' ')[-4..-1]
    $password = -join($password[0],$password[1],$password[2],$password[3],($SpecialCharacter | Get-Random))

    write-output $password

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

        import-module MSOnline

        import-module ExchangeOnlineManagement

        import-module AzureADPreview

        Connect-ExchangeOnline -ShowBanner:$false

        connect-azuread

        Connect-MsolService

        }

    function Get-ExchangeOnlineManagement {

        Set-PSRepository -Name "PSgallery" -InstallationPolicy Trusted

        Install-Module -Name ExchangeOnlineManagement -scope currentuser

        }

    Function Get-MSonline {

        Set-PSRepository -Name "PSgallery" -InstallationPolicy Trusted

        Install-Module MSOnline -scope currentuser

        }

    function Get-AzureAD {

        Set-PSRepository -Name "PSgallery" -InstallationPolicy Trusted

        install-module AzureADPreview -scope currentuser

    }


    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement)
        {
            write-host " "
            write-host "Exchange online Management exists"
        }
    else
        {
            Write-host "Exchange Online Management module does not exist. Attempting to download..."
            Get-ExchangeOnlineManagement
        }


    if (Get-Module -ListAvailable -Name MSOnline)
        {
            write-host "MSOnline exists"
        }
    else
        {
            Write-host "MSOnline module does not exist. Attempting to download..."
            Get-MSOnline
        }

    if (Get-Module -ListAvailable -Name AzureAD)
        {
            write-host "AzureAD exists, removing...."
            remove-module -name AzureAD -ErrorAction SilentlyContinue | Out-Null
            uninstall-module -name AzureAD -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -path "C:\Program Files\WindowsPowerShell\modules\AzureAD" -recurse -force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -path "C:\Program Files (x86)\WindowsPowerShell\modules\AzureAD" -recurse -force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -path (([Environment]::GetFolderPath("MyDocuments"))+"\WindowsPowerShell\modules\AzureAD") -recurse -force -ErrorAction SilentlyContinue | Out-Null

            if (Get-Module -ListAvailable -Name AzureADpreview)
                {

                    write-host "AzureADpreview exists"

                }
            else
                {

                    Write-host "AzureADPreview module does not exist. Attempting to download..."
                    Get-AzureAD

                }

        }
    else
        {

            Write-host "AzureADPreview module does not exist. Attempting to download..."
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
                    write-output "Starting local account breach"

                }

            else
                {

                    write-host -ForegroundColor Red "This 365 tenant has ADConnect. Please run this script on a domain controller."

                    pause

                }


        }

    else
        {

            start-CloudAccountBreach
            write-output "Starting cloud account breach"

        }

}

function get-upn {

    $script:upn = Read-Host "Enter the UPN of the breached account"

    if (Get-MsolUser -UserPrincipalName $script:upn -ErrorAction SilentlyContinue)
        {

            Write-host "User found..."

        }

    else
        {

            write-host "User not found, try again"
            get-upn

        }

}

function Set-NewCloudPassword {

    $Script:NewCloudPassword = Get-NewPassword

    Set-MsolUserPassword -UserPrincipalName $script:upn -NewPassword $Script:NewCloudPassword -ForceChangePassword $false | Out-Null

}

function set-NewLocalPassword {

    $Script:NewLocalPassword = Get-NewPassword

    $SecureLocalPassword = ConvertTo-SecureString $script:NewLocalPassword -AsPlainText -force

    get-aduser -filter "userPrincipalName -eq '$script:upn'" | Set-ADAccountPassword -newpassword $SecureLocalPassword | Out-Null

}

function revoke-365Access {

    Revoke-AzureADUserAllRefreshToken -ObjectId $script:upn

}

function remove-RestrictedUser {

    Remove-BlockedSenderAddress -SenderAddress $script:upn

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

    Start-Transcript -path "$Script:DesktopPath\AccountBreach.txt"

    print-TecharyLogo

    if($script:UPNs)
        {

            foreach ($Script:UPN in $script:UPNs)
                {

                    Set-NewCloudPassword

                    revoke-365Access

                    remove-RestrictedUser

                    disable-maliciousRules

                    write-host "The password has been reset to $script:NewCloudPassword"

                    write-host "`nA transcript of this script has been saved to $Script:DesktopPath\AccountBreach.txt.
                                `nPlease now call the user, if you haven't already, and run through getting outlook set back up.
                                `nOnce outlook has been setup, please then run through oulook rules with the user, as ALL rules have been disabled. Some may actually be in use."

                    pause

                }


        }
    else
        {

            get-upn

            Set-NewCloudPassword

            revoke-365Access

            remove-RestrictedUser

            disable-maliciousRules

            write-host "The password has been reset to $script:NewCloudPassword"

            write-host "`nA transcript of this script has been saved to $Script:DesktopPath\AccountBreach.txt.
                        `nPlease now call the user, if you haven't already, and run through getting outlook set back up.
                        `nOnce outlook has been setup, please then run through oulook rules with the user, as ALL rules have been disabled. Some may actually be in use."

            pause

        }

    Stop-Transcript

}

function start-LocalAccountBreach {

    Start-Transcript -path "$Script:DesktopPath\AccountBreach.txt"

    print-TecharyLogo

    if($script:UPNs)
        {

            foreach ($script:upn in $script:UPNs)
                {

                    set-NewLocalPassword

                    revoke-365Access

                    remove-RestrictedUser

                    disable-maliciousRules

                    write-host "The password has been reset to $script:newlocalpassword, please perform a directory sync in ADConnect.
                                `nThe login locations for $script:upn have been saved to $Script:DesktopPath\LoggedInLocations.csv.
                                `nA transcript of this script has been saved to $Script:DesktopPath\AccountBreach.txt.
                                `nPlease now call the user, if you haven't already, and run through setting them back up with logging back into their PC with their new password, re-setting up 365 apps, and ensuring the VPN credentials are cleared if required.
                                `nOnce outlook is setup, please then run through outlook rules with the user, as ALL rules have been disabled. Some may actually be in use."

                    pause

                }

        }
    else
        {

            get-upn

            set-NewLocalPassword

            revoke-365Access

            remove-RestrictedUser

            disable-maliciousRules

            write-host "The password has been reset to $script:newlocalpassword, please perform a directory sync in ADConnect.
                        `nThe login locations for $script:upn have been saved to $Script:DesktopPath\LoggedInLocations.csv.
                        `nA transcript of this script has been saved to $Script:DesktopPath\AccountBreach.txt.
                        `nPlease now call the user, if you haven't already, and run through setting them back up with logging back into their PC with their new password, re-setting up 365 apps, and ensuring the VPN credentials are cleared if required.
                        `nOnce outlook is setup, please then run through outlook rules with the user, as ALL rules have been disabled. Some may actually be in use."

            pause

        }


    Stop-Transcript

}

$Script:DesktopPath = [Environment]::GetFolderPath("Desktop")

connect-365

if ($csv)
    {

        $script:UPNs = import-csv $CSV

    }


get-ADConnectStatus