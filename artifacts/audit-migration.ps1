$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$catalog = Get-Content "$root/src/Rules/requirements/internal-catalog.json" -Raw | ConvertFrom-Json
$aliases = (Get-Content "$root/src/Rules/requirements/legacy-aliases.json" -Raw | ConvertFrom-Json).aliases
$profiles = (Get-Content "$root/src/Rules/requirements/internal-profiles.json" -Raw | ConvertFrom-Json).profiles
$index = @{}
foreach ($r in $catalog.requirements) { $index[$r.id] = $r }
function Get-AuditChecks($requirements) {
    foreach ($r in $requirements) {
        foreach ($o in $r.obligations) { foreach ($c in $o.checks) { $c } }
        if ($null -ne $r.execution_variants) {
            foreach ($v in $r.execution_variants.PSObject.Properties) {
                foreach ($o in $v.Value.obligations) { foreach ($c in $o.checks) { $c } }
            }
        }
    }
}
$globalCheckNames = @(Get-AuditChecks $catalog.requirements | ForEach-Object { $_.name })
function Resolve-AuditAlias([string]$id, [string[]]$trail = @()) {
    if ($index.ContainsKey($id)) { return $id }
    if ($trail -contains $id) { throw "Alias cycle: $id" }
    foreach ($next in $aliases.$id) { Resolve-AuditAlias $next ($trail + $id) }
}
$old = @(Get-ChildItem "$root/src/Rules/controls" -Filter 'MB-C*.json' | ForEach-Object { (Get-Content $_.FullName -Raw | ConvertFrom-Json).rules } | Where-Object { $_.verification -ne 'manual' })
$rows = foreach ($r in $old) {
    $ids = @(Resolve-AuditAlias $r.id | Sort-Object -Unique)
    $mapped = @($ids | ForEach-Object { $index[$_] })
    $checks = @(Get-AuditChecks $mapped)
    $oldNames = @($r.checks.name | Sort-Object -Unique)
    $missing = @($oldNames | Where-Object { $_ -notin $checks.name })
    $globalMissing = @($missing | Where-Object { $_ -notin $globalCheckNames })
    $argumentChanges = @()
    foreach ($c in $r.checks) {
        $sameName = @($checks | Where-Object { $_.name -eq $c.name })
        if ($sameName.Count -gt 0) {
            $exact = @($sameName | Where-Object { ($_.args | ConvertTo-Json -Depth 40 -Compress) -eq ($c.args | ConvertTo-Json -Depth 40 -Compress) })
            if ($exact.Count -eq 0) { $argumentChanges += $c.name }
        }
    }
    $automatic = @($mapped | Where-Object { !$_.human_evidence.required -and $_.verification -ne 'manual' -and @($_.obligations | Where-Object { $_.role -ne 'supporting' -and $_.proof -eq 'human' }).Count -eq 0 })
    [pscustomobject]@{
        legacy_id=$r.id; title=$r.title; canonical_ids=($ids -join ','); old_checks=($oldNames -join ',')
        missing_mapped_checks=($missing -join ','); missing_global_checks=($globalMissing -join ',')
        changed_argument_checks=($argumentChanges -join ','); human_required_ids=(@($mapped | Where-Object { $_.human_evidence.required } | ForEach-Object { $_.id }) -join ',')
        fully_automatic_ids=($automatic.id -join ',')
        baseline_ids=(@($ids | Where-Object { $_ -in $profiles.baseline.requirement_ids }) -join ',')
        baseline_default_local_ids=(@($automatic | Where-Object { $_.id -in $profiles.baseline.requirement_ids -and 'LOCAL' -in $_.target_modes } | ForEach-Object { $_.id }) -join ',')
    }
}
$rows | Export-Csv "$PSScriptRoot/migration-automation-audit.csv" -NoTypeInformation -Encoding UTF8
[pscustomobject]@{
 legacy_automated=$old.Count
 missing_alias=@($rows | Where-Object { !$_.canonical_ids }).Count
 missing_mapped_check_rules=@($rows | Where-Object { $_.missing_mapped_checks }).Count
 missing_global_check_rules=@($rows | Where-Object { $_.missing_global_checks }).Count
 argument_changed_rules=@($rows | Where-Object { $_.changed_argument_checks }).Count
 fully_automatic_mapped_rules=@($rows | Where-Object { $_.fully_automatic_ids }).Count
 human_only_mapped_rules=@($rows | Where-Object { !$_.fully_automatic_ids }).Count
 default_baseline_local_covered_rules=@($rows | Where-Object { $_.baseline_default_local_ids }).Count
} | ConvertTo-Json
$rows | Where-Object { $_.missing_mapped_checks } | Format-List
