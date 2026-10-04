@echo off
cd /d C:\Users\Apps\Downloads\com.penti.app\adj9\rev
C:\Python314\python.exe -X utf8 mint_session_chain.py > mint_session_chain.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> mint_session_chain.log