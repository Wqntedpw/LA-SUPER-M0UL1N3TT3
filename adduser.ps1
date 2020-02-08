<#
.NAME
LA-SUPER-M0UL1N3TT3

.AUTHOR
Enzo

.DESCRIPTION
Ce script importe des infos depuis un CSV pour :
    - Créer un utilisateur avec un mdp temporaire
    - Lui envoi un email avec son id et le mot de passe temporaire
    - Créer un repertoire dans partage

.SCOPE
Serveur AD

.NOTES
    Le script principale se trouve dans la fonction adduserad().

    A voir:
        - Le script crée le groupe si il n'existe pas
#>

# Variables
$csv = import-csv -path "C:\Users\Administrateur\Documents\users.csv" -delimiter ";"
$mailsecurestring = "C:\Users\Administrateur\Documents\mailpassword.xml"
$logpath="C:\Users\Administrateur\Documents\"
$logfile = "adduser-$(get-date -UFormat "%d-%m-%y_%H-%M-%S").log"
$domainfqdn="nsa.local"
$domain=$domainfqdn.Split(".")[0]
$domainext=$domainfqdn.Split(".")[1]
$domainpath=(-join ("DC=","$domain",",","DC=","$domainext"))
$GlobalPendingOU="Pending"
$UsersPengingOU="Users"
$GroupPendingOU="Groups"
$ShareRepertory="C:\Partage\Users"

# Vérification du module NTFSSecurity
if (Get-Module NTFSSecurity) {Write-Host "Le module NTFSecurity est isntallé"} else {Install-Module -Name NTFSSecurity}

# Création du fichier de logs
new-item -Path $logpath -ItemType File -Name $logfile


# Generation de caracteres
function get-randomstring () {
    param (
        [int]$Length,
        $type
    )
    if ($type -eq "alpha") { $set = "abcdefghijklmnopqrstuvwxyz0123456789#$".ToCharArray() } elseif ($type -eq "num") { $set = "1234567890".ToCharArray() } else { exit }
    $result = ""
    for ($x = 0; $x -lt $Length; $x++) {
       $result += $set | Get-Random
    }
    return $result
}


# Envoi de mail
function sendmail () {
    param (
        $emailext
    )
    $mailuser = "devlab@qmail.pm"
    $mailpassword = Get-Content -Path $mailsecurestring | ConvertTo-SecureString
    $mailcredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $mailuser, $mailpassword
    $mailbody = “<p><img src='https://i.imgur.com/1UrGu3V.png?2'> <h2>Création de compte</h2> </p><br><p>Bonjour $displayname ! <br><br>Voici les informations sur votre compte BND:<br>Nom d'utilisateur: $samname <br>Mot de passe temporaire: $pass <br></p><p style='text-color: red;'>Un nouveau mot de passe vous sera demandé lors de votre première connexion</p>”
                        <# VV! A CHANGER !VV #>
    Send-MailMessage -To “starrcsgo@gmail.com” -From $mailuser -Subject “Création de votre compte BND” -Body $mailbody -Credential $mailcredential -SmtpServer “ns.noroute.pw” -Port 587 -UseSsl -BodyAsHtml -Encoding UTF8
}

# Ajout-Creation de l'OU
function adduserou () {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -like '$oushort'")) {
            New-ADOrganizationalUnit -Name "$oushort" -Path "$domainpath"
    }
}

# Ajout-Creation de groupe
function addusergroup () {
    if (-not (Get-ADGroup -Filter "Name -eq '$group' -and GroupCategory -eq 'Security'")){
        New-ADGroup -Name "$group" -Displayname "$group" -Path "OU=$GroupPendingOU,OU=$GlobalPendingOU,DC=nsa,DC=local" -GroupCategory Security -GroupScope Global
    }

    Add-ADGroupMember -Identity "$group" -Members "$samname"
}

# Création du repertoire personnel
function createrepertory () {
    if (-not (Get-Item -Path "${ShareRepertory}\${samname}")) {
        New-Item -ItemType Directory -Path "$ShareRepertory" -Name "$samname"
        $acl = Get-Acl "${ShareRepertory}\${samname}"
        $acl.SetOwner([System.Security.Principal.NTAccount]"NSA\$samname") <# DOMAINE EN DUR A MODIFIER #>
        $acl.SetAccessRuleProtection($true,$true)
        #$everyone = New-Object system.security.AccessControl.FileSystemAccessRule("Tout le monde","Read",,,"Allow")
        #$acl.RemoveAccessRuleAll($everyone)
        $acl |Set-Acl
        Remove-NTFSAccess -AccessRights "ReadAndExecute, Synchronize" -Account "Tout le monde" -Path "${ShareRepertory}\${samname}" -AccessType "allow" -AppliesTo ThisFolderSubfoldersAndFiles
        Add-NTFSAccess -Path "${ShareRepertory}\${samname}" -Account "NSA\$samname" -AccessRights FullControl

    }
}

# Ajout de l'utilisateur
function adduserad () {
    foreach ($user in $csv)
    {
        # Recuperation des infos du CSV
        $pass = get-randomstring 16 alpha
        $nom = $user.lastname
        $prenom = $user.firstname
        $ou = $user.ou
        $oushort= $user.ou.Split("=")[1].Split(",")[0]
        $group = $user.group
        $emailext = $user.emailext
        $displayname = (-join ("$prenom"," ","$nom"))
        $samname = (-join ("$prenom",".","$nom")).ToLower()

        # Verif si un utilisateur existant n'a pas le meme nom
        while (get-aduser -Filter "UserPrincipalName -eq '${samname}@${domain}' -or Samaccountname -eq '${samname}'"){
            write-host "[DEBUG]" "Le compte $samname existe"
            $r = get-randomstring 3 num
            $samname = (-join ("$samname","$r"))
            $displayname = (-join ("$prenom"," ","$nom"," ","$r"))
        }

        write-host "[DEBUG]" " Nom : $nom , Prenom : $prenom , OU : $ou , SAM : $samname , Pass : $pass"

        # Création de l'utilisateur 
        New-ADuser -surname $nom -name $displayname -SamAccountName $samname -UserPrincipalName ${samname}@${domainfqdn} -givenname $prenom -displayname $displayname -Path $ou -ChangePasswordAtLogon $true -PasswordNeverExpires $false -AccountPassword (ConvertTo-SecureString -AsPlainText $pass -Force) -Enabled $true
        
        # Envoi du mail
        sendmail $emailext

        # Ajout de l'utilisateur dans son groupe
        addusergroup

        # Creation du repertoire personnel
        createrepertory
     }
}

adduserad

