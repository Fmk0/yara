rule Vidar_Stealer : Vidar 
{
    meta:
        description = "Yara rule for detecting Vidar stealer"
        author = "Fumik0_"

    strings:
        $mz = { 4D 5A }

        $s1  = "Versions: %s" wide ascii
        $s2  = "files\\Soft\\Authy" wide ascii
        $s3  = "Soft: The Bat!" wide ascii
        $s4  = "Password: %s" wide ascii
        $s5  = "nss3.dll" wide ascii
        $s6  = "msvcp140.dll" wide ascii
        $s7  = "mozglue.dll" wide ascii
        $s8  = "freebl3.dll" wide ascii
        $s9  = "vcruntime140.dll" wide ascii
        $s10 = "softokn3.dll" wide ascii
        
    condition:
        $mz at 0 and ( (all of ($s*)) )
}

rule Vidar_variant_1 : Vidar 
{
    meta:
        description = "Yara rule for detecting Vidar stealer - First official versions"
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
