# The DC that stopped applying its security policy

Part 2 of the [WEF/WEC write-up](README.md). While adding a domain controller to the logging pilot, one forwarding event kept coming back every five minutes. It led to a DC that had silently stopped applying the security settings of its GPOs, because its copy of one file carried a different timestamp from the PDC's copy. Same content, different date.

> Everything below comes from a lab. Names, addresses and figures are fictitious or rounded. The mechanism described here is deduced from Process Monitor traces; Microsoft does not document it. Read it as a field report, not as a reference.

## The symptom nobody would have seen

The lab runs [HardenAD](https://github.com/LoicVeirman/HardenAD), adapted to the lab, which reapplies DC policies every five minutes. On a healthy DC that means one successful Security extension cycle every five minutes. On the broken one (call it DC2):

| Indicator | Healthy DC | DC2 |
| --- | --- | --- |
| `GroupPolicy/Operational`, Security extension | 4016 then 5016 (code 0) | 4016 then **7016, code 1252**, every cycle |
| `Application`, SceCli 1704 ("security policy applied") | every 5 minutes | none since the last reboot |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SeCEdit\LastWinLogonConfig` | time of the last cycle | frozen |
| `C:\Windows\security\templates\policies` | `gpt000xx` templates recreated every cycle | empty |
| Other extensions (registry, preferences, advanced audit) | OK | OK |

Code 1252 is `ERROR_OVERRIDE_NOCHANGES`: "call the extension again even if nothing changed". It reads like a retry request, not an error, which is part of why nothing looks broken.

And nothing was broken in the visible sense. Settings already applied stay in place. What stops is everything new: user rights, security options (Kerberos, NTLM, LDAP and SMB signing), service and file ACLs, restricted groups, and the correction of local drift. The five-minute reapply no longer reverts a setting someone changed by hand.

We found it by chance. DC2 had just joined the WEF pilot, and its `Microsoft-Windows-Forwarding/Operational` log showed event 106 ("subscription policy has changed") at every policy cycle. We have not proven why the failed cycles produced those 106 events, but without them nobody would have looked.

## What we ruled out

The Security extension was stopping before reading a single GPO, so everything about policy content was a dead end. For the record, none of these changed anything:

- SYSVOL content: same file count and the same `GptTmpl.inf` files on every DC.
- GPO versions: AD and SYSVOL versions identical.
- The local security database: moving `secedit.sdb` away and restoring it gave the same failure.
- Engine configuration: the `SeCEdit` and `GPExtensions\{827D…}` keys were identical to a healthy DC, apart from the frozen timestamp.
- The WEF pilot settings: a full rollback changed nothing.
- Updates: no package installed between the last good boot and the failure; installing the next CU afterwards changed nothing.
- Forest and domain functional level: lowering it changed nothing.
- A Windows Server 2025 bug: a Windows Server 2022 DC with the same GPOs was healthy (until we reproduced the failure on it, see below).
- DFSR: only the expected disconnections around partner reboots.
- File access: Process Monitor during a cycle showed no access denied. The engine refused without reading or writing anything.

Two beliefs were also wrong along the way. The server half of the security engine runs in `services.exe`, not in LSASS: Process Monitor shows `services.exe` writing `secedit.sdb`. And a single 7016 in the first minutes after boot is not specific to the broken DC: on our Windows Server 2025 PDC it appears at nearly every boot since the April 2026 CU (a correlation we have not proven), and the next cycle succeeds.

## Where it actually stops

The Security extension has two halves:

1. The client (`scecli.dll`, in the Group Policy service) runs at every cycle. It empties `C:\Windows\security\templates\policies`, then asks the server half for permission to work.
2. The server (`scesrv.dll`, in `services.exe`) answers. If it agrees, the client copies the `GptTmpl.inf` files from SYSVOL and the server merges and applies them.

On a healthy DC the server starts working within a millisecond (registry reads, database open). On DC2 the answer 1252 came back in about 20 ms with no file or registry operation at all: the decision came from state already in memory.

That state is set at boot. A boot-time Process Monitor capture on both DCs showed the same startup task in the security engine:

| Moment | PDC (DC1) | DC2 |
| --- | --- | --- |
| ~20 s after boot | Reads its own copy of the Default Domain Controllers Policy `GptTmpl.inf` through `\\DC1\SYSVOL`: BAD NETWORK PATH (SYSVOL not shared yet) | Same on `\\DC2\SYSVOL` |
| ~5.5 min after boot, second attempt | Reads the attributes of its own copy | Reads its own copy, looks up the PDC, reads the attributes of **the PDC's copy** |
| Then | Reads the file, opens the database, first SceCli 1704 | Lists both folders, then no engine activity at all for 16 hours |

At that moment the three copies looked like this:

| Copy | Last write time | SHA-256 |
| --- | --- | --- |
| DC1 (PDC) | T | identical |
| DC2 | T − 11 s | identical |
| DC3 (received by replication later) | T | identical |

Our reading: a DC that is not the PDC compares its copy of the Default Domain Controllers Policy with the PDC's at boot. If the dates differ, it waits for SYSVOL to converge before allowing the Security extension to run. The convergence never comes, because DFSR only replicates content changes and the content was identical. The task does not check again: the DC stays blocked until its next boot.

That also explains the timing. The 11-second gap was written about five months before the failure. DC2 simply had not rebooted since, and the problem only shows up at boot. The PDC compares with itself, so it always recovers; that is the "one 7016 after boot, then fine" pattern above.

## Proving it in both directions

| Step | Copies | DC rebooted | Result |
| --- | --- | --- | --- |
| 1. A trivial edit of the Default Domain Controllers Policy in GPMC on the PDC (one setting defined, then removed) | PDC ends **0.73 s** ahead of the other copies, same hash | DC2 | Still 7016 / 1252 |
| 2. No change: is Windows Server 2022 affected? | same | DC3 (WS2022, healthy that morning) | 7016 / 1252 at every cycle |
| 3. PDC copy's last write time aligned on the others | all equal | DC2 and DC3 | 5016 and SceCli 1704 at every cycle |

One variable, flipped both ways, on two OS versions: Windows Server 2025 (April and October 2026 CUs) and Windows Server 2022 (June 2026 CU).

Step 1 also shows the probable trigger. GPMC seems to write `GptTmpl.inf` twice in a row on the PDC. The first write replicates; the second has identical content, so DFSR never sends it, and the PDC keeps a slightly newer date. We observed it twice out of two. But if every GPMC edit did this, the problem would be common and well known, so the exact conditions are still open.

Step 3 changed the file's timestamp directly in SYSVOL on the PDC. That is acceptable in a lab. **It is not a production procedure.** In production, start with the read-only check below and open a case with Microsoft.

## Checking your own DCs

Read-only, from any machine that can read SYSVOL on the DCs. It compares the last write time of the Default Domain Controllers Policy security template on every DC with the PDC's, down to the tick:

```powershell
$Guid = '{6AC1786C-016F-11D2-945F-00C04fB984F9}'   # Default Domain Controllers Policy, same GUID in every domain
$Domain = (Get-ADDomain).DNSRoot
$Pdc = (Get-ADDomain).PDCEmulator
$Rel = "Policies\$Guid\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

$Ref = Get-Item "\\$Pdc\SYSVOL\$Domain\$Rel"
Get-ADDomainController -Filter * | ForEach-Object {
    $f = Get-Item "\\$($_.HostName)\SYSVOL\$Domain\$Rel" -ErrorAction SilentlyContinue
    [pscustomobject]@{
        DC          = $_.HostName
        LastWrite   = if ($f) { $f.LastWriteTimeUtc.ToString('o') } else { 'unreadable' }
        SameAsPdc   = $f -and ($f.LastWriteTimeUtc.Ticks -eq $Ref.LastWriteTimeUtc.Ticks)
        SameContent = $f -and ((Get-FileHash $f.FullName).Hash -eq (Get-FileHash $Ref.FullName).Hash)
    }
} | Format-Table -AutoSize
```

A DC with `SameAsPdc = False` and `SameContent = True` is, by our reading, a DC that will block at its next boot.

To detect a DC that is already blocked, two signals:

- **The 7016 itself**, forwarded by WEF. The subscription query has to match exactly, so filter on the extension ID:

  ```xml
  <Select Path="Microsoft-Windows-GroupPolicy/Operational">
    *[System[Provider[@Name='Microsoft-Windows-GroupPolicy'] and EventID=7016]]
    and *[EventData[Data[@Name='CSEExtensionId']='{827D319E-6EAC-11D2-A4EA-00C04F79F83A}']]
  </Select>
  ```

  Alert on two consecutive cycles in 7016 for the same DC. One isolated 7016 right after a boot is normal on our Windows Server 2025 DCs. The forwarder needs read access to that channel, like any other (see trap 1 in part 1).

- **The age of `LastWinLogonConfig`** (seconds since 1 January 1980, UTC). With a five-minute policy cycle, anything older than about 30 minutes means the security policy is not being applied, whatever the cause.

To see the engine's own view, `ExtensionDebugLevel = 2` (DWORD) under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` writes to `C:\Windows\security\logs\winlogon.log`. A blocked DC logs a 1252 when "sending control flag 1 via the server" and nothing after it. Remove the value afterwards.

## Is it a security issue?

Creating the gap requires editing the Default Domain Controllers Policy or writing to SYSVOL on a DC: tier 0 already. So there is no privilege escalation. An attacker who already has tier 0 could use it to freeze policy application on a DC so their local changes are not reverted, with a few 7016 events as the only trace. That is defence evasion, not access.

Transferring the PDC role does not fix it. Each DC compares itself with the current PDC, so moving the role to a DC with an older copy would move the problem to the others, and the blocked DC still needs a reboot.

## What is still open

| Question | Status |
| --- | --- |
| The internal mechanism | Deduced from Process Monitor, not documented by Microsoft |
| Which attribute is compared | Almost certainly LastWriteTime; the metadata change time differs between DCs and does not block |
| How often GPMC causes the gap | Seen 2 times out of 2 here; cannot be systematic or it would be well known |
| Affected versions | WS2025 and WS2022 at the CUs above; 2019 and older builds untested |
| PDC role transfer | Predicted from the mechanism, not tested |

Two failures (one natural, one provoked) and one fix, in one domain. Solid for a lab, small as a sample. If you run the check above on your DCs and find a mismatch, or have seen 7016 with code 1252 on the Security extension, an issue here would help.

## References

- Microsoft Learn: [System error codes 1000–1299](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-) (1252, `ERROR_OVERRIDE_NOCHANGES`)
- Microsoft Sysinternals: [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- HardenAD: [LoicVeirman/HardenAD](https://github.com/LoicVeirman/HardenAD), open-source Active Directory hardening toolkit
