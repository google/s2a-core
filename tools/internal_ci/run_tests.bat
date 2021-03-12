choco install bazel -y --version 4.0.0 --limit-output
cd github/s2a-core
set PATH=C:\tools\msys64\usr\bin;C:\Python27;%PATH%
bazel test --test_output=errors //...
set BAZEL_EXITCODE=%errorlevel%
exit /b %BAZEL_EXITCODE%
