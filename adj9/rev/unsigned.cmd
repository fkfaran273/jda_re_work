@echo off
cd /d C:\Users\Apps\Downloads\com.penti.app\adj9\rev
C:\Python314\python.exe -X utf8 unsigned_test.py > unsigned.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> unsigned.log