# deauth attack

## How to use

```bash
syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]
sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
```

## Example

```bash
deauth-attack mon0 00:11:22:33:44:55
-> AP Broadcast deauth

deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
-> AP unicast / Station unicast deauth

deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB -auth
-> Authentication 프레임 전송
```
