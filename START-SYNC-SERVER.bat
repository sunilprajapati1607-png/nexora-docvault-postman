@echo off
rem Nexora DocVault Sync Server - on this PC or an in-house server (needs Node.js 20 or newer).
rem The sealed copy is kept in the "data" folder beside this file. Open the server's port (8790) to the PCs that join.
cd /d "%~dp0"
if "%DV_SYNC_PASSWORD%"=="" set /p DV_SYNC_PASSWORD=Server password (at least 12 characters):
if "%DV_SYNC_DATA%"=="" set "DV_SYNC_DATA=%~dp0data"
node server.mjs
pause
