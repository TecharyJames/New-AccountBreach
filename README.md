# New-AccountBreach
 
This script will:

    1. Check if your 365 tenant has any directory sync settings enabled. 
    2. If so, direct you to run the script on a DC, if it is not already.
    3. Connects to 365.
    4. Requests the UPN of the breached user.
    5. Reset the password of the breached user.
    6. Revoke all Azure AD refresh tokens.
    7. Remove the account from the 'Restricted users' in 365.
    8. Export all login locations to $env:userprofile\LoggedInLocations.csv.
    9. Disable all inbox rules on the breached account.

# How To

    1. Download the .ps1 file
    2. Right click > Run with powershell
    3. Profit!

If you have any suggestions or feedback, or even any issues with this script please feel free to email me on jtarran@techary.com!