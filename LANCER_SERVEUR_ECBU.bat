@echo off
cd /d %~dp0
python server.py --host 0.0.0.0 --port 8000
pause
