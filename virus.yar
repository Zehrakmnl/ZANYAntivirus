rule VirV1
{
    strings:
        $vi = "virus" nocase wide ascii 
        $vi2 = "open target ?? File" nocase wide ascii 
        $vi3 = "nuse File::Find" nocase wide ascii 
        $vi4 = "target" nocase wide ascii  
    condition:
        all of them or ($vi and $vi3)
}

rule VirV2
{
    strings:
        $vi = "File.open" nocase wide ascii 
        $vi2 = "fle.read(1)" nocase wide ascii 
        $vi3 = "cdir.each " nocase wide ascii 
        $vi4 = "basename" nocase wide ascii  
        
    condition:
        all of them 
        
}


rule VirV3
{
    strings:
        $vi = "SocratesDecrypt" nocase wide ascii 
        $vi2 = "Explode" nocase wide ascii 
        $vi3 = "ord" nocase wide ascii 
        $vi4 = "exec" nocase wide ascii  
        $vi5 = "fread" nocase wide ascii  
        
    condition:
        all of them 
        
}
