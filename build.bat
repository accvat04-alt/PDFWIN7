@echo off
REM Chay tren may Windows co Python 3.8 (co the la Windows 7 hoac Windows 10).
REM Python 3.8 phai cung kieu 32/64-bit voi DLL token.
python -m pip install --upgrade pip
python -m pip install -r requirements.txt || goto :err
python -m PyInstaller --noconfirm --onedir --name KySoPDF ^
  --collect-all pyhanko --collect-all pyhanko_certvalidator --collect-all pkcs11 ^
  --collect-all certifi --collect-all reportlab --hidden-import pkcs11._pkcs11 ^
  agent.py || goto :err
copy /Y config.json dist\KySoPDF\config.json
copy /Y index.html dist\KySoPDF\index.html
echo.
echo Xong. Thu muc chay: dist\KySoPDF  (chay KySoPDF.exe)
pause
exit /b 0
:err
echo Co loi, xem thong bao phia tren.
pause
exit /b 1
