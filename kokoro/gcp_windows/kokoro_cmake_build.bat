set PATH=C:\tools\msys64\usr\bin;C:\Python27;%PATH%

cd %KOKORO_ARTIFACTS_DIR%\github\s2a-core

call tools/internal_ci/run_cmake_build.bat
exit %ERRORLEVEL%
