# Cisco IOS via agent SNMP

Monitors Cisco IOS switches with the items, discovery rules and triggers of the official Zabbix 7.0 template **Cisco IOS by SNMP**. It is meant for switches the Zabbix server cannot reach. A **Windows host running Zabbix Agent 2** performs the SNMP v2c queries for the server.

**Nothing to install:** the SNMP client is a plain PowerShell script that uses only what Windows already includes. Deployment is copy and paste.

```
Zabbix server ──agent 10050/TCP──> Windows + Zabbix Agent 2 ──SNMP v2c 161/UDP──> Cisco switch
                                    zbx_snmp.ps1
```

## Files

| File | Where it goes |
|---|---|
| `zbx_snmp.ps1` | Windows host: `C:\Program Files\Zabbix Agent 2\scripts\zbx_snmp.ps1` |
| `zabbix_agent2.d/cisco_snmp_via_agent.conf` | Windows host: `C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\` |
| `template_cisco_ios_via_agent_snmp.json` | Zabbix: *Data collection → Templates → Import* |

## Requirements

- Zabbix server **7.0**, and **Zabbix Agent 2** on Windows (PowerShell 5.1, built into Windows).
- The Zabbix server can reach the agent on **10050/TCP**.
- The Windows host can reach each switch on **161/UDP**.
- Each switch allows SNMP v2c read access from the Windows host:
  ```
  snmp-server community <community> RO [<acl>]
  ```
  If an ACL is used, it must permit the Windows host IP.
- The community contains only `A–Z a–z 0–9 - _ .`. The agent rejects other characters unless `UnsafeUserParameters=1` is set.

---

## 1. Windows host

### 1.1 Script
1. Create the folder `C:\Program Files\Zabbix Agent 2\scripts\`.
2. Open Notepad, paste the content of `zbx_snmp.ps1`, and save it as `C:\Program Files\Zabbix Agent 2\scripts\zbx_snmp.ps1`.

If you copied the **file** instead of pasting the text, remove the "downloaded from internet" mark. Run in PowerShell as Administrator:
```powershell
Unblock-File "C:\Program Files\Zabbix Agent 2\scripts\zbx_snmp.ps1"
```

### 1.2 Test against one switch
Run in PowerShell:
```powershell
cd "C:\Program Files\Zabbix Agent 2\scripts"
powershell -NoProfile -ExecutionPolicy Bypass -File .\zbx_snmp.ps1 check <switch-ip> <community>
powershell -NoProfile -ExecutionPolicy Bypass -File .\zbx_snmp.ps1 get   <switch-ip> <community> 1.3.6.1.2.1.1.5.0
powershell -NoProfile -ExecutionPolicy Bypass -File .\zbx_snmp.ps1 walk  <switch-ip> <community> 1.3.6.1.2.1.31.1.1.1.1
powershell -NoProfile -ExecutionPolicy Bypass -File .\zbx_snmp.ps1 ping  <switch-ip>
```
Expected output:

| Command | Output |
|---|---|
| `check` | `1` (the switch answers SNMP) |
| `get` | `.1.3.6.1.2.1.1.5.0 = STRING: "<switch name>"` |
| `walk` | interface names, one per line |
| `ping` | `{"up":1,"loss":0,"rtt":0.001}` |

If `check` returns `0`, the `get` command prints the reason as `SNMP ERROR: ...`. Fix that before continuing.

### 1.3 UserParameters
Copy `cisco_snmp_via_agent.conf` to `C:\Program Files\Zabbix Agent 2\zabbix_agent2.d\`. The default Windows install has an `Include=` line for this folder in `zabbix_agent2.conf`. If yours doesn't, paste these lines at the end of `zabbix_agent2.conf` instead:
```
UserParameter=snmp.walk[*],powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\scripts\zbx_snmp.ps1" walk "$1" "$2" "$3"
UserParameter=snmp.icmp[*],powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\scripts\zbx_snmp.ps1" ping "$1"
UserParameter=snmp.get[*],powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\scripts\zbx_snmp.ps1" get "$1" "$2" "$3"
UserParameter=snmp.check[*],powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\scripts\zbx_snmp.ps1" check "$1" "$2"
```
`-ExecutionPolicy Bypass` lets the agent run the unsigned script without changing the system's execution policy.

### 1.4 Restart the agent and test through it
```powershell
Restart-Service "Zabbix Agent 2"
cd "C:\Program Files\Zabbix Agent 2"
.\zabbix_agent2.exe -c .\zabbix_agent2.conf -t 'snmp.get[<switch-ip>,<community>,1.3.6.1.2.1.1.5.0]'
```
If the output says `Unknown metric`, the UserParameters are not loaded. `sc.exe qc "Zabbix Agent 2"` shows which config file the service actually uses.

---

## 2. Zabbix

### 2.1 Import the template
*Data collection → Templates → Import* → `template_cisco_ios_via_agent_snmp.json`, with all rules ticked (Update existing, Create new, Delete missing).

### 2.2 Create one host per switch
*Data collection → Hosts → Create host*

| Field | Value |
|---|---|
| Host name | switch name, e.g. `SW-BUILDING-A-01` |
| Templates | **only** *Cisco IOS via agent SNMP*. Do not also add *Cisco IOS by SNMP*, because the item keys collide. |
| Interfaces | **Agent**, IP = **Windows host**, port `10050` |
| Macros | `{$SNMP.TARGET}` = switch IP, `{$SNMP_COMMUNITY}` = community (type *Secret text* recommended) |
| Inventory | *Automatic* (optional: fills model, serial number, location and OS) |

For the next switches, **clone** the host and change the *Host name* and `{$SNMP.TARGET}`.

### 2.3 Verify
After 1–2 minutes, check *Monitoring → Latest data*:
- **SNMP polling status** shows `OK`.
- **SNMP agent availability** shows `1`.
- Interfaces, CPU, memory and sensors appear after discovery runs. To run it now, use **Execute now** on the item *SNMP walk via agent: monitoring data*.

---

## How it works

The template has 3 items that query the agent. Everything else is a *dependent item* or *dependent discovery rule* that takes its data from them, with the same keys, OIDs, filters and triggers as *Cisco IOS by SNMP*.

| Agent item | Interval | Content |
|---|---|---|
| `snmp.walk[...]` **monitoring data** | `{$SNMP.WALK.INTERVAL}` = 1m | uptime, interfaces (IF-MIB, EtherLike-MIB), CPU, memory, temperature, fans, PSUs |
| `snmp.walk[...]` **inventory** | `{$SNMP.INVENTORY.INTERVAL}` = 15m | system group, ENTITY-MIB (model, serial numbers) |
| `snmp.icmp[...]` | 1m | 3× ICMP ping from the Windows host |

The script prints the walk in the same text format as Zabbix's native SNMP `walk[]`, so the standard *SNMP walk to JSON* / *SNMP walk value* preprocessing works unchanged. On failure it prints one line, `SNMP ERROR: <reason>`. That line is shown in the item **SNMP polling status**.

## Differences from *Cisco IOS by SNMP*

- SNMP polling goes through the Windows agent. The host has an **Agent** interface, so a green **ZBX** icon means the Windows agent is up, not the switch.
- ICMP ping, loss and response time are measured **from the Windows host**.
- SNMP availability comes from the item `snmp.available` instead of `zabbix[host,snmp,available]`.
- **No SNMP traps**, because an agent cannot receive them.
- SNMP **v2c only**.

## Optional host macros

| Macro | Default | Purpose |
|---|---|---|
| `{$SNMP.WALK.INTERVAL}` | `1m` | polling interval of monitoring data |
| `{$SNMP.INVENTORY.INTERVAL}` | `15m` | polling interval of inventory data |
| `{$SNMP.TIMEOUT}` | `5m` | how long without SNMP data before *No SNMP data collection* fires |
| `{$IFCONTROL}`, `{$IFCONTROL:"Gi1/0/1"}` | `1` | link-down alerts for all ports / one port (`0` = off) |
| `{$NET.IF.IFNAME.NOT_MATCHES}` etc. | see template | interfaces excluded from discovery |
| `{$IF.UTIL.MAX}`, `{$CPU.UTIL.CRIT}`, `{$MEMORY.UTIL.MAX}`, `{$TEMP_WARN}`, … | see template | trigger thresholds |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Unknown metric snmp.walk` | UserParameters not loaded, or agent not restarted (steps 1.3–1.4) |
| *SNMP polling status* = `SNMP ERROR: Timeout…` | wrong switch IP or community, the switch ACL does not permit the Windows host, or 161/UDP is blocked |
| Items *Not supported* with `invalid OID format` | the walk returned an error; see *SNMP polling status* |
| *Timeout while gathering data* | very large switch or stack: raise the item timeout (30s) and `$TotalBudgetSec` in the script |
| All switches lose data at once | the Windows host or its agent is down |
| A discovery rule (e.g. temperature) finds nothing | the switch does not support that Cisco MIB; this is expected |

**Load:** about 3–4 s of PowerShell per switch per minute. For many switches, raise `{$SNMP.WALK.INTERVAL}` to `2m`.
