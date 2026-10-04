@echo off
cd /d C:\Users\Apps\Downloads\com.penti.app\adj9\rev
C:\Python314\python.exe -X utf8 replica_recipe.py > rr.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> rr.log