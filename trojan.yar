

rule TrojV1
{
    strings:
        $T1 = "action=$_POST" wide ascii
        $T2 = "mysql.info.php" wide ascii
        $T3 = "mysql_connect" wide ascii
        $T4 = "mysql_fetch_row" wide ascii
        $T5 = "ereg_replace" wide ascii
        $T6 = "stripslashes" wide ascii
        $T7 = " 22 33 444" wide ascii
    condition:
        all of them or ($T7)
        
}

rule TrojV2
{
    strings:
        $T1 = "/usr/sbin/sendmail -t" wide ascii
        $T2 = "mailprog" wide ascii
        $T3 = "open MAIL, " wide ascii
        $T4 = "REMOTE_ADDR" wide ascii
        $T5 = "REMOTE_HOST" wide ascii

    condition:
        all of them
        
}

rule TrojV3
{
    strings:
        $T1 = "from Crypto.Hash import SHA256" wide ascii
        $T2 = "import struct" wide ascii
        $T3 = "import glob " wide ascii
        $T4 = "getKey??" wide ascii
        $T5 = "expanduser('~??Desktop')" wide ascii

    condition:
        all of them
        
}

rule TrojV4
{
    strings:
        $T1 = "trojan" wide ascii

    condition:
        all of them
        
}