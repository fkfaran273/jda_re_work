@echo off
cd /d C:\Users\Apps\Downloads\com.penti.app\adj9\rev
C:\Python314\python.exe -X utf8 verify_map_blob.py > vmb.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> vmb.log