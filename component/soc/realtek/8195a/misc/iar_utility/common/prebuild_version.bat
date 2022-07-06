echo off

set COMPILE_TIME=%date:~10,4%/%date:~4,2%/%date:~7,2%-%time:~0,8%
set SVNVER=""
for /f "tokens=*" %%a in ('svnversion -n') do set SVNVER=%%a
::del version.c

if exist %1_version.c (
del %1_version.c
)

echo const char %1_rev[] = "%1_ver_%SVNVER%__%COMPILE_TIME%"; >> %1_version.c