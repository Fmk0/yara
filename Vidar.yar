rule Vidar_Stealer : Vidar 
{
    meta:
        description = "Yara rule for detecting Vidar stealer"
        author = "Fumik0_"

    strings:
        $mz = { 4D 5A }

        $s1 = { 56 69 64 61 72 }
        $s2 = { 31 42 45 46 30 41 35 37 42 45 31 31 30 46 44 34 36 37 41 }
    condition:
        $mz at 0 and ( (all of ($s*)) )
}

rule Vidar_Early : Vidar 
{
    meta:
        description = "Yara rule for detecting Vidar stealer - Early versions"
        author = "Fumik0_"

    strings:
        $mz = { 4D 5A }
        $s1 =  { 56 69 64 61 72 }
        $hx1 = { 56 00 69 00 64 00 61 00 72 00 2E 00 63 00 70 00 70 00 }
    condition:
         $mz at 0 and all of ($hx*) and not $s1
}

rule AntiVidar : Vidar 
{
    meta:
        description = "Yara rule for detecting Anti Vidar - Vidar Cracked Version"
        author = "Fumik0_"

    strings:
        $mz = { 4D 5A }
        $s1 = { 56 69 64 61 72 }
        $hx1 = { 56 00 69 00 64 00 61 00 72 00 2E 00 63 00 70 00 70 00 }
        $hx2 = { 78 61 6B 66 6F 72 2E 6E  65 74 00 }
    condition:
         $mz at 0 and all of ($hx*) and not $s1
}
