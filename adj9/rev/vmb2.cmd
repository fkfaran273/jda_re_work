@echo off
cd /d C:\Users\Apps\Downloads\com.penti.app\adj9\rev
C:\Python314\python.exe -u -X utf8 verify_map_blob2.py > vmb2.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> vmb2.log