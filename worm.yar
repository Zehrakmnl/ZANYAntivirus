 

rule WormV1
{
    strings:
        $ro = "tworm.exe" nocase wide ascii
        $ro2 = "REMOTE_ADDR.inc " nocase wide ascii
        $ro3 = "fread" nocase wide ascii
        $ro4 = "content" nocase wide ascii
        
    condition:
        all of them
        
}

rule WormV3
{
    strings:
        $ro = "WSADATA"  wide ascii
        $ro2 = "LOBYTE"  wide ascii
        $ro3 = "WSAStartup"  wide ascii
        $ro4 = "HIBYTE"  wide ascii 
        $ro5 = "InitWinSock"  wide ascii
	    $ro6 = "NO_IMSPREAD"  wide ascii        
    condition:
        all of them
        
}

rule WormV4
{
    strings:
        $ro = "dos.h"  wide ascii
        $ro2 = "mapi.h"  wide ascii
        $ro3 = "extern"  wide ascii
        $ro4 = "DWORD dwSize"  wide ascii 
        $ro5 = "LHANDLE lhSession"  wide ascii
	    $ro6 = "lpEntryID"  wide ascii        
    condition:
        all of them
        
}

rule WormV5
{
    strings:
        $ro = "propogateDrive"  wide ascii
        $ro2 = "Attribute = hidden"  wide ascii
        $ro3 = "EARTH_WORM_JIM"  wide ascii   
    condition:
        all of them
        
}
