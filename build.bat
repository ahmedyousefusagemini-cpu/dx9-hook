rem ============================================================================
rem Push compiled DLL to physical local machine via RDP
rem ============================================================================
set "SOURCE_DLL=%~dp0Release\D3DX9_43.dll"
set "DEST_DIR=\\tsclient\D\AhmedProject\client\Env_DX9"

echo.
echo Pushing DLL to local machine (%DEST_DIR%)...

if not exist "%DEST_DIR%" (
    echo WARNING: Destination "%DEST_DIR%" not found. 
    echo Ensure your Local Drives are shared in your Remote Desktop Connection settings.
) else (
    rem The /Y flag suppresses the overwrite prompt and forces the overwrite
    copy /Y "%SOURCE_DLL%" "%DEST_DIR%\"
    
    if errorlevel 1 (
        echo ERROR: Failed to copy the file. Make sure the target file is not currently in use/locked.
    ) else (
        echo SUCCESS: Overwrote D3DX9_43.dll on local machine.
    )
)
