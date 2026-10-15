# Detection output — `synthetic-security-log.csv`

Events analysed: **348** · Alerts: **7**

| Time | Rule | Severity | ATT&CK | Summary |
|---|---|---|---|---|
| 2026-03-09 08:12:00 | DET-01 Brute force | high | T1110.001 | 42 failed RDP logons for 'Administrator' from 203.0.113.77 between 08:12:00 and 08:16:47 |
| 2026-03-09 08:16:54 | DET-04 Account lockout | medium | T1110 | 'Administrator' locked out |
| 2026-03-09 09:40:00 | DET-02 Password spray | high | T1110.003 | 28 distinct accounts failed from 10.20.10.187 in 8 min |
| 2026-03-09 09:49:32 | DET-03 Success after failures | critical | T1078 | 'user17' logged on from 10.20.10.187 after 28 failures from that source in the previous 30 min |
| 2026-03-09 09:55:32 | DET-05 Account created | medium | T1136.002 | 'helpdesk_tmp' created by 'user17' |
| 2026-03-09 09:56:32 | DET-06 Privileged group change | critical | T1098 | 'helpdesk_tmp' added to 'Domain Admins' by 'user17' |
| 2026-03-09 10:04:32 | DET-07 Security log cleared | critical | T1070.001 | Audit log cleared by 'user17' |
