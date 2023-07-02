rule KeylV1
{
    strings:
        $pythonKeylogger = "import win32api" nocase wide ascii
        $log = "keylog.txt" nocase wide ascii
        $key = "SetWindowsHookEx" nocase wide ascii


    condition:
        all of them 
}

rule KeylV2 {
    
    strings:
        $asm1 = "ComStart: " wide ascii
        $asm2 = "VirParSize" wide ascii
        $asm3 = "equ 4Ch" wide ascii
        $asm4 = "Jmp_Prg" wide ascii
        $asm5 = "repz" wide ascii
        $asm6 = "DosBel3" wide ascii
    
    condition:
        all of them or ($asm2 and $asm3)
        
        
}

rule KeylV3
{
    strings:
        $k1 = "diPlus.h" wide ascii
        $k2 = "crtdefs" wide ascii
        $k3 = "ios::app" wide ascii
        $k4 = "log_error_file" wide ascii
        $k5 = "clsidEncoder" wide ascii
        $k6 = "KBDLLHOOKSTRUCT" wide ascii
        $k7 = "DWORD"  wide ascii

    condition:
        all of them or ($k3 and $k4) or ($k6 and $k7)
        
}
