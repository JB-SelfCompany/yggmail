@echo off
REM Build script for Yggmail Android Library
REM This script builds the AAR file for Android integration

echo ========================================
echo Yggmail Android Library Build Script
echo ========================================
echo.

REM Set Android SDK path
set ANDROID_HOME=your\path\to\sdk
set ANDROID_SDK_ROOT=your\path\to\sdk

REM Check if Android SDK exists
if not exist "%ANDROID_HOME%" (
    echo ERROR: Android SDK not found at %ANDROID_HOME%
    echo Please update ANDROID_HOME path in this script
    pause
    exit /b 1
)

echo Android SDK: %ANDROID_HOME%
echo.

REM Check if gomobile is installed
where gomobile >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: gomobile not found in PATH
    echo Please install gomobile:
    echo   go install golang.org/x/mobile/cmd/gomobile@latest
    echo   gomobile init
    pause
    exit /b 1
)

echo Building Android AAR...
echo.

REM Build for all architectures (larger file, better compatibility)
echo Building for all architectures (arm, arm64, 386, amd64)...
echo Note: Using -checklinkname=0 to workaround wlynxg/anet compatibility issue
echo.
gomobile bind -target=android -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/neilalexander/yggmail/mobile

REM Save error level immediately
set BUILD_RESULT=%ERRORLEVEL%

echo.
if %BUILD_RESULT% EQU 0 (
    echo ========================================
    echo Build successful!
    echo ========================================
    echo.
    echo Output files:
    if exist yggmail.aar (
        dir yggmail.aar 2>nul | find "yggmail"
    )
    if exist yggmail-sources.jar (
        dir yggmail-sources.jar 2>nul | find "yggmail"
    )
    echo.
    echo To use in Android project:
    echo   1. Copy yggmail.aar to app/libs/
    echo   2. Add to build.gradle: implementation files('libs/yggmail.aar')
    echo.
    pause
    exit /b 0
) else (
    echo ========================================
    echo Build FAILED!
    echo ========================================
    echo.
    echo Check the error messages above
    echo.
    pause
    exit /b 1
)
