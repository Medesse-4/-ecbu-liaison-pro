@echo off
netsh advfirewall firewall add rule name="ECBU Liaison Pro 8000" dir=in action=allow protocol=TCP localport=8000
pause
