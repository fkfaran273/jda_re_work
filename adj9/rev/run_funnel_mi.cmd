@echo off
cd /d C:\Users\Apps\Downloads\com.penti.app\adj9\rev
C:\Python314\python.exe -X utf8 run_funnel.py --device dev_mi.json --gps 274418fe-880e-4739-9a7f-1ee44c61ab7d --referrer "adjust_reftag=cA1DXYdvcrG5k&utm_source=VKM+Digital+Yeni&utm_campaign=AH&utm_content=vkm_0926_36&utm_term=penti_generic" --link "https://app.adjust.com/1sd1lk6a?campaign=AH&adgroup=vkm_0926_36&creative=penti_generic&click_id=274418fe-880e-4739-9a7f-1ee44c61ab7d&idfa=274418fe-880e-4739-9a7f-1ee44c61ab7d" via-device noproxy > run_funnel.log 2>&1
echo EXITCODE=%ERRORLEVEL% >> run_funnel.log
