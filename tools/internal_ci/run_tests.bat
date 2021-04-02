choco install bazel -y --version 4.0.0 --limit-output
cd github/s2a-core
set PATH=C:\tools\msys64\usr\bin;C:\Python27;%PATH%

:: The OpenSSL library used in OpenSSL-specific tests is only configured to run
:: on Linux, so omit targets with the "openssl" tag.
echo "Running tests..."
bazel test --test_output=errors --test_tag_filters=-openssl --build_tag_filters=-openssl //...

echo "Running ASAN tests..."
bazel test --config=asan --test_output=errors --test_tag_filters=-openssl --build_tag_filters=-openssl //...

echo "Running MSAN tests..."
bazel test --config=msan --test_output=errors --test_tag_filters=-openssl --build_tag_filters=-openssl //...

echo "Running TSAN tests..."
bazel test --config=tsan --test_output=errors --test_tag_filters=-openssl --build_tag_filters=-openssl //...
set BAZEL_EXITCODE=%errorlevel%
exit /b %BAZEL_EXITCODE%
