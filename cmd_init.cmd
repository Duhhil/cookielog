@echo off
REM cmd_init.cmd -- useful aliases and tools for cmd.exe
REM EDUCATIONAL USE ONLY - FOR SECURITY RESEARCH AND TRAINING
REM This runs automatically on every cmd startup (via AutoRun registry key)
REM alongside Clink injection.

REM ------------------------------------------------------------------ Linux-style aliases
doskey ls=dir /b $*
doskey ll=dir /a /o-d $*
doskey la=dir /a $*
doskey l=dir /b $*
doskey cat=type $*
doskey grep=findstr /s /i /n $*
doskey which=where $*
doskey clear=cls
doskey pwd=cd
doskey touch=copy /b nul $1 /b 2>nul
doskey mv=move $*
doskey cp=copy $*
doskey rm=del /q $*
doskey mkdir2=mkdir $1 2>nul ^&^& echo created $1
doskey head=more +0 $1
doskey tail=powershell -c "Get-Content $1 -Tail $2"
doskey wc=powershell -c "(Get-Content $1).Count"

REM ------------------------------------------------------------------ Navigation
doskey ..=cd ..
doskey ...=cd ..\..
doskey ....=cd ..\..\..
doskey cd=cd /d $*

REM ------------------------------------------------------------------ Git shortcuts
doskey gs=git status $*
doskey gl=git log --oneline -10 $*
doskey ga=git add $*
doskey gc=git commit -m $1
doskey gp=git push $*
doskey gd=git diff $*
doskey gb=git branch $*

REM ------------------------------------------------------------------ Python shortcuts
doskey py=python $*
doskey pi=pip install $*
doskey pf=python -m py_compile $1

REM ------------------------------------------------------------------ Cookielog shortcuts
doskey cl_auto=python auto.py $*
doskey cl_pick=python pick.py $*
doskey cl_listen=python listen.py $1
doskey cl_sink=python sink.py
doskey cl_build=build.bat
doskey cl_test=test_curl.bat $1
doskey cl_loot=if exist loot dir loot
doskey cl_ifec=if exist ifec dir ifec

REM ------------------------------------------------------------------ Better tools (if installed)
REM bat = syntax-highlighted cat
doskey b=bat $*
REM rg = fast grep (ripgrep)
doskey r=rg --line-number $*

REM ------------------------------------------------------------------ Prompt customization
REM Clink already handles the prompt; this is a fallback if clink fails.
REM Format: [dir] >
REM Uncomment to use a custom prompt:
REM @prompt $E[92m$P$E[0m$G 

REM ------------------------------------------------------------------ Environment info
REM Show current dir on startup (only in interactive sessions)
if /i "%1"=="" (
    echo [cmd] %CD%
)
