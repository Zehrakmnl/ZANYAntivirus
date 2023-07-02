rule RoTKV1
{
    strings:
        $ro = "#include <linux/kernel.h>" nocase wide ascii
        $ro2 = "hideProcess.h" nocase wide ascii
        $ro3 = "KERN_ALERT" nocase wide ascii
        $ro4 = "find_task_by_pid" nocase wide ascii
        
    condition:
        ($ro2) or all of them

}

rule RoTKV2
{
    strings:
        $ro = "GET_ADDR(printk, %eax)" nocase wide ascii
        $ro2 = "#include xde.inc " nocase wide ascii
        $ro3 = "subl $0x20, %esp " nocase wide ascii
        $ro4 = "leal  ?? (%ebp), %eax" nocase wide ascii
        $ro5 = "movl $-1, retcode" nocase wide ascii
        $ro6 = ".byte 0x00; .long 0x000000FF; .long 0x00000075;" nocase wide ascii
        
    condition:
        all of them
        
}

rule RoTKV3
{
    strings:
        $r1 = "#include rootkit.hpp" nocase wide ascii
        $r2 = "PsLookupProcessByProcessId" nocase wide ascii
        $r3 = "STATUS_SUCCESS" nocase wide ascii
        $r4 = "ZwOpenProcess" nocase wide ascii
        $r5 = "ZwSetInformationProcess" nocase wide ascii
        
       
    condition:
        ($r1) or all of them 
}


