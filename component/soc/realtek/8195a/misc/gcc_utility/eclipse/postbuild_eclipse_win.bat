:: application/Debug
@echo off

set bindir=.
set tooldir=..\..\..\..\..\..\component\soc\realtek\8195a\misc\iar_utility\common\tools
set libdir=..\..\..\..\..\..\component\soc\realtek\8195a\misc\bsp
set gccdir=..\..\..\..\..\..\tools\arm-none-eabi-gcc\4_8-2014q3\bin

set /a secure_boot = 0

::echo %tooldir%
::echo %libdir%

::copy bootloader and convert from image to object file
::copy ../../../../../component/soc/realtek/8195a/misc/bsp/image/ram_1.r.bin ram_1.r.bin
::%gccdir%/arm-none-eabi-objcopy --rename-section .data=.loader.data,contents,alloc,load,readonly,data -I binary -O elf32-littlearm -B arm ram_1.r.bin ram_1.r.o 

::del Debug/Exe/target.map Debug/Exe/application.asm *.bin
cmd /c "%gccdir%\arm-none-eabi-nm %bindir%/application.axf | %tooldir%\sort > %bindir%/application.nm.map"
cmd /c "%gccdir%\arm-none-eabi-objdump -d %bindir%/application.axf > %bindir%/application.asm"


for /f "delims=" %%i in ('cmd /c "%tooldir%\grep __ram_image2_text_start__ %bindir%/application.nm.map | %tooldir%\gawk '{print $1}'"') do set ram2_start=0x%%i
for /f "delims=" %%i in ('cmd /c "%tooldir%\grep __sdram_data_start__ %bindir%/application.nm.map | %tooldir%\gawk '{print $1}'"') do set ram3_start=0x%%i

for /f "delims=" %%i in ('cmd /c "%tooldir%\grep __ram_image2_text_end__ %bindir%/application.nm.map  | %tooldir%\gawk '{print $1}'"') do set ram2_end=0x%%i
for /f "delims=" %%i in ('cmd /c "%tooldir%\grep __sdram_data_end__ %bindir%/application.nm.map  | %tooldir%\gawk '{print $1}'"') do set ram3_end=0x%%i

::echo %ram1_start% > tmp.txt
echo %ram2_start%
echo %ram3_start%
::echo %ram1_end% >> tmp.txt
echo %ram2_end%
echo %ram3_end%


%gccdir%\arm-none-eabi-objcopy -j .image2.start.table -j .ram_image2.text -j .ram_image2.rodata -j .ram.data -Obinary %bindir%/application.axf %bindir%/ram_2.bin
if NOT %ram3_start% == %ram3_end% (
	%gccdir%\arm-none-eabi-objcopy -j .sdr_text -j .sdr_rodata -j .sdr_data -Obinary %bindir%/application.axf %bindir%/sdram.bin
)

%tooldir%\pick %ram2_start% %ram2_end% %bindir%\ram_2.bin %bindir%\ram_2.p.bin body+reset_offset+sig
%tooldir%\pick %ram2_start% %ram2_end% %bindir%\ram_2.bin %bindir%\ram_2.ns.bin body+reset_offset
if defined %ram3_start (
%tooldir%\pick %ram3_start% %ram3_end% %bindir%\sdram.bin %bindir%\ram_3.p.bin body+reset_offset
)

:: force update ram_2_for_hash.bin and ram_3_for_hash.bin
if exist %bindir%\ram_2_for_hash.bin del %bindir%\ram_2_for_hash.bin
if exist %bindir%\ram_3_for_hash.bin del %bindir%\ram_3_for_hash.bin

if %secure_boot%==1 (%tooldir%\tail.exe -c +17 %bindir%\ram_2.p.bin > %bindir%\ram_2_for_hash.bin)
if defined %ram3_start (
if %secure_boot%==1 (%tooldir%\tail.exe -c +17 %bindir%\ram_3.p.bin > %bindir%\ram_3_for_hash.bin)
)

:: force update ram_1.p.bin
del %bindir%\ram_1.p.bin

:: check ram_1.p.bin exist, copy default
if not exist %bindir%\ram_1.p.bin (
	copy %libdir%\image\ram_1.p.bin %bindir%\ram_1.p.bin
)

::padding ram_1.p.bin to 32K+4K+4K+4K, LOADER/RSVD/SYSTEM/CALIBRATION
%tooldir%\padding 44k 0xFF %bindir%\ram_1.p.bin

:: Signature ram_2.bin
if exist %bindir%\ram_2_for_hash.bin (
	python %tooldir%\hashing.py %bindir%\ram_2_for_hash.bin
	copy %bindir%\output.bin %bindir%\hash_sum_2.bin
	%tooldir%\ed25519.exe sign %bindir%\hash_sum_2.bin %bindir%\..\..\..\keypair.json
	tail -c 64 %bindir%\hash_sum_2.bin > %bindir%\signature_ram_2
	python %tooldir%\reheader.py %bindir%\ram_2.p.bin
	python %tooldir%\reheader.py %bindir%\ram_2.ns.bin
	copy /b %bindir%\ram_2.p.bin+%bindir%\signature_ram_2 %bindir%\ram_2.p.bin
	copy /b %bindir%\ram_2.ns.bin+%bindir%\signature_ram_2 %bindir%\ram_2.ns.bin
)

:: Signature sdram.bin
if exist %bindir%\ram_3_for_hash.bin (
	python %tooldir%\hashing.py %bindir%\ram_3_for_hash.bin
	copy %bindir%\output.bin %bindir%\hash_sum_3.bin
	%tooldir%\ed25519.exe sign %bindir%\hash_sum_3.bin %bindir%\..\..\..\keypair.json
	tail -c 64 %bindir%\hash_sum_3.bin > %bindir%\signature_ram_3
	python %tooldir%\reheader.py %bindir%\ram_3.p.bin
	copy /b %bindir%\ram_3.p.bin+%bindir%\signature_ram_3 %bindir%\ram_3.p.bin
)

:: SDRAM case
if defined %ram3_start (
copy /b %bindir%\ram_1.p.bin+%bindir%\ram_2.p.bin+%bindir%\ram_3.p.bin %bindir%\ram_all.bin
copy /b %bindir%\ram_2.ns.bin+%bindir%\ram_3.p.bin %bindir%\ota.bin
)

:: NO SDRAM case
if not defined %ram3_start (
copy /b %bindir%\ram_1.p.bin+%bindir%\ram_2.p.bin %bindir%\ram_all.bin
copy /b %bindir%\ram_2.ns.bin %bindir%\ota.bin
)

%tooldir%\checksum %bindir%\ota.bin

del ram_1.r.*
del ram*.p.bin
del ram*.ns.bin
del ram_2.bin
if exist sdram.bin (
	del sdram.bin
)

exit
