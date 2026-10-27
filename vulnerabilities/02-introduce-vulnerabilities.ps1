<#
    02-introduce-vulnerabilities.ps1
    Lab AD Attack/Defense - lab.local
    A executer sur DC01, en PowerShell (Administrateur)

    Introduit des faiblesses volontaires, DOCUMENTEES, pour servir
    de cibles lors de la phase "Attaque" depuis Kali.
    Chaque faille est commentee : ce qu'elle est, pourquoi elle est
    exploitable, et quelle attaque elle permet. Reutilise ces
    commentaires dans ton dossier vulnerabilities/ du depot GitHub.
#>

Import-Module ActiveDirectory

$domainDN = (Get-ADDomain).DistinguishedName
$ouUtilisateurs = "OU=Utilisateurs,OU=LAB-CORP,$domainDN"

# ===========================================================
# FAILLE 1 : Mot de passe faible / predictible
# ---------------------------------------------------------
# Compte utilisateur avec un mot de passe trivial, du type
# qu'on retrouve dans les wordlists classiques (rockyou.txt).
# Attaque possible : password spraying ou brute force depuis
# Kali (crackmapexec, hydra, ou simplement un essai manuel).
# ===========================================================
$weakPassword = ConvertTo-SecureString "Password1" -AsPlainText -Force

New-ADUser `
    -Name "Paul Girard" `
    -GivenName "Paul" -Surname "Girard" `
    -SamAccountName "paul.girard" `
    -UserPrincipalName "paul.girard@lab.local" `
    -Path $ouUtilisateurs `
    -AccountPassword $weakPassword `
    -Enabled $true `
    -ChangePasswordAtLogon $false `
    -Title "Stagiaire Commercial" `
    -ErrorAction SilentlyContinue

Write-Host "[FAILLE 1] Compte 'paul.girard' cree avec mot de passe faible : Password1" -ForegroundColor Red

# ===========================================================
# FAILLE 2 : Compte de service avec SPN (Kerberoasting)
# ---------------------------------------------------------
# Un compte avec un Service Principal Name (SPN) enregistre
# peut se voir demander un ticket Kerberos TGS par N'IMPORTE
# QUEL utilisateur authentifie du domaine, sans droits
# particuliers. Ce ticket est chiffre avec le hash du mot de
# passe du compte de service -> si ce mot de passe est faible,
# il peut etre casse hors ligne (offline) avec hashcat/john
# apres extraction via Kali (Impacket GetUserSPNs.py, Rubeus).
# ===========================================================
$svcPassword = ConvertTo-SecureString "SqlService2023" -AsPlainText -Force

New-ADUser `
    -Name "svc-sql" `
    -SamAccountName "svc-sql" `
    -UserPrincipalName "svc-sql@lab.local" `
    -Path $ouUtilisateurs `
    -AccountPassword $svcPassword `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "Compte de service SQL (demo Kerberoasting)" `
    -ErrorAction SilentlyContinue

# Enregistrement du SPN sur ce compte
setspn -A MSSQLSvc/dc01.lab.local:1433 svc-sql

Write-Host "[FAILLE 2] Compte 'svc-sql' cree avec SPN MSSQLSvc/dc01.lab.local:1433 (Kerberoasting)" -ForegroundColor Red

# ===========================================================
# FAILLE 3 : Compte sans pre-authentification Kerberos (AS-REP Roasting)
# ---------------------------------------------------------
# Quand la pre-authentification Kerberos est desactivee sur un
# compte, N'IMPORTE QUI peut demander un ticket AS-REP pour ce
# compte SANS connaitre son mot de passe. Une partie du ticket
# est chiffree avec le hash du mot de passe du compte -> peut
# etre casse hors ligne, meme sans etre authentifie au domaine.
# Attaque Kali : Impacket GetNPUsers.py.
# ===========================================================
$asrepPassword = ConvertTo-SecureString "Welcome2024!" -AsPlainText -Force

New-ADUser `
    -Name "Karim Ammar" `
    -GivenName "Karim" -Surname "Ammar" `
    -SamAccountName "karim.ammar" `
    -UserPrincipalName "karim.ammar@lab.local" `
    -Path $ouUtilisateurs `
    -AccountPassword $asrepPassword `
    -Enabled $true `
    -Title "Technicien reseau" `
    -ErrorAction SilentlyContinue

# Desactive la pre-authentification Kerberos sur ce compte
Set-ADAccountControl -Identity "karim.ammar" -DoesNotRequirePreAuth $true

Write-Host "[FAILLE 3] Compte 'karim.ammar' cree SANS pre-authentification Kerberos (AS-REP Roasting)" -ForegroundColor Red

# ===========================================================
# FAILLE 4 : Partage reseau trop ouvert
# ---------------------------------------------------------
# Un dossier partage accessible en lecture (voire ecriture) par
# "Tout le monde" / "Utilisateurs authentifies", sans
# restriction par groupe. Souvent utilise pour stocker des
# fichiers sensibles par erreur (mots de passe en clair,
# scripts avec identifiants, etc.) -> cible classique pour
# l'enumeration SMB (smbclient, enum4linux, crackmapexec)
# ===========================================================
$sharePath = "C:\PartageRH"
New-Item -Path $sharePath -ItemType Directory -ErrorAction SilentlyContinue

# Fichier "appat" avec une fausse info sensible, pour simuler
# une decouverte juteuse lors de l'enumeration SMB
Set-Content -Path "$sharePath\notes_admin.txt" -Value @"
Pense-bete (a ne pas laisser ici en vrai !) :
- Compte svc-sql utilise pour les sauvegardes SQL
- Ne pas oublier de changer le mdp du compte stagiaire paul.girard
"@

New-SmbShare -Name "PartageRH" -Path $sharePath -FullAccess "Tout le monde" -ErrorAction SilentlyContinue

Write-Host "[FAILLE 4] Partage SMB 'PartageRH' cree avec acces complet pour 'Tout le monde'" -ForegroundColor Red

# ===========================================================
Write-Host ""
Write-Host "=== Recapitulatif des failles introduites ===" -ForegroundColor Yellow
Write-Host "1. paul.girard       / Password1       -> password spraying"
Write-Host "2. svc-sql           / SqlService2023   -> Kerberoasting (SPN)"
Write-Host "3. karim.ammar       / Welcome2024!     -> AS-REP Roasting (no preauth)"
Write-Host "4. \\DC01\PartageRH                     -> enumeration SMB / acces trop ouvert"
Write-Host ""
Write-Host "Documente chacune dans vulnerabilities/ de ton depot avant de passer a l'attaque." -ForegroundColor Yellow
