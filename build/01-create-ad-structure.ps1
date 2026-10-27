<#
    01-create-ad-structure.ps1
    Lab AD Attack/Defense - lab.local
    A executer sur DC01, en PowerShell (Administrateur)

    Cree une arborescence d'OU + des groupes + des utilisateurs
    pour simuler une petite entreprise. Aucune faille volontaire
    n'est introduite ici (ce sera un script separe).
#>

Import-Module ActiveDirectory

$domainDN = (Get-ADDomain).DistinguishedName   # ex: DC=lab,DC=local

# ---------------------------------------------------------
# 1. Unites d'organisation (OU)
# ---------------------------------------------------------
$ouRoot = "LAB-CORP"
$ous = @("Direction", "IT", "Comptabilite", "Commercial", "Utilisateurs", "Serveurs", "Groupes")

New-ADOrganizationalUnit -Name $ouRoot -Path $domainDN -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue

foreach ($ou in $ous) {
    New-ADOrganizationalUnit -Name $ou -Path "OU=$ouRoot,$domainDN" -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
    Write-Host "OU creee : $ou" -ForegroundColor Green
}

$ouDirection    = "OU=Direction,OU=$ouRoot,$domainDN"
$ouIT           = "OU=IT,OU=$ouRoot,$domainDN"
$ouCompta       = "OU=Comptabilite,OU=$ouRoot,$domainDN"
$ouCommercial   = "OU=Commercial,OU=$ouRoot,$domainDN"
$ouUtilisateurs = "OU=Utilisateurs,OU=$ouRoot,$domainDN"
$ouGroupes      = "OU=Groupes,OU=$ouRoot,$domainDN"

# ---------------------------------------------------------
# 2. Groupes de securite
# ---------------------------------------------------------
$groupes = @(
    @{Nom="G-Direction";    Desc="Equipe direction"},
    @{Nom="G-IT";           Desc="Equipe IT / support"},
    @{Nom="G-Comptabilite"; Desc="Equipe comptabilite"},
    @{Nom="G-Commercial";   Desc="Equipe commerciale"},
    @{Nom="G-Admins-Lab";   Desc="Administrateurs du lab (a utiliser avec parcimonie)"}
)

foreach ($g in $groupes) {
    New-ADGroup -Name $g.Nom -GroupScope Global -GroupCategory Security `
        -Path $ouGroupes -Description $g.Desc -ErrorAction SilentlyContinue
    Write-Host "Groupe cree : $($g.Nom)" -ForegroundColor Green
}

# ---------------------------------------------------------
# 3. Utilisateurs
#    Mot de passe commun pour le lab (a changer / documenter
#    comme fictif dans ton README, ne jamais le commiter)
# ---------------------------------------------------------
$defaultPassword = ConvertTo-SecureString "LabPass2026!" -AsPlainText -Force

$utilisateurs = @(
    @{Prenom="Claire";  Nom="Dupont";   SamAccountName="claire.dupont";  OU=$ouDirection;  Groupe="G-Direction";    Titre="Directrice Generale"},
    @{Prenom="Marc";     Nom="Lefevre"; SamAccountName="marc.lefevre";   OU=$ouIT;         Groupe="G-IT";           Titre="Administrateur Systeme"},
    @{Prenom="Sophie";   Nom="Bernard"; SamAccountName="sophie.bernard"; OU=$ouIT;         Groupe="G-IT";           Titre="Technicienne Support"},
    @{Prenom="Julien";   Nom="Moreau";  SamAccountName="julien.moreau";  OU=$ouCompta;     Groupe="G-Comptabilite";Titre="Comptable"},
    @{Prenom="Nadia";    Nom="Khelifi"; SamAccountName="nadia.khelifi";  OU=$ouCompta;     Groupe="G-Comptabilite";Titre="Responsable Comptable"},
    @{Prenom="Thomas";   Nom="Petit";   SamAccountName="thomas.petit";   OU=$ouCommercial; Groupe="G-Commercial";  Titre="Commercial"},
    @{Prenom="Lea";      Nom="Garcia";  SamAccountName="lea.garcia";     OU=$ouCommercial; Groupe="G-Commercial";  Titre="Commerciale"},
    @{Prenom="Asma";     Nom="Saidi";   SamAccountName="asma.saidi";     OU=$ouIT;         Groupe="G-Admins-Lab";  Titre="Etudiante / Admin du lab"}
)

foreach ($u in $utilisateurs) {
    $upn = "$($u.SamAccountName)@lab.local"
    $displayName = "$($u.Prenom) $($u.Nom)"

    New-ADUser `
        -Name $displayName `
        -GivenName $u.Prenom `
        -Surname $u.Nom `
        -SamAccountName $u.SamAccountName `
        -UserPrincipalName $upn `
        -Path $u.OU `
        -AccountPassword $defaultPassword `
        -Enabled $true `
        -ChangePasswordAtLogon $false `
        -Title $u.Titre `
        -ErrorAction SilentlyContinue

    Add-ADGroupMember -Identity $u.Groupe -Members $u.SamAccountName -ErrorAction SilentlyContinue

    Write-Host "Utilisateur cree : $displayName ($($u.SamAccountName)) -> $($u.Groupe)" -ForegroundColor Cyan
}

# ---------------------------------------------------------
# 4. G-Admins-Lab devient Admin du domaine (pratique pour le lab)
# ---------------------------------------------------------
Add-ADGroupMember -Identity "Domain Admins" -Members "asma.saidi" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Termine ===" -ForegroundColor Yellow
Write-Host "Mot de passe par defaut pour tous les comptes crees : LabPass2026!" -ForegroundColor Yellow
Write-Host "Pense a verifier dans 'Utilisateurs et ordinateurs Active Directory' (dsa.msc)" -ForegroundColor Yellow
