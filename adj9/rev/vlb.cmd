@echo off
cd /d C:\Users\Apps\Downloads\com.penti.app\adj9\rev
C:\Python314\python.exe -u -X utf8 verify_law_blob.py > vlb.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> vlb.log