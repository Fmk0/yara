rule Predator_The_Thief : Predator_The_Thief {
    meta:
        description = "Yara rule for Predator The Thief v2.3.5 & +"
        author = "Fumik0_"
        date = "2018/10/12"
        update = "2018/12/19"

    strings:
        $mz = { 4D 5A }

        // V2
        $hex1 = { BF 00 00 40 06 } 
        $hex2 = { C6 04 31 6B }
        $hex3 = { C6 04 31 63 }
        $hex4 = { C6 04 31 75 }
        $hex5 = { C6 04 31 66 }
 
        $s1 = "sqlite_" ascii wide
 
        // V3
        $x1 = { C6 84 24 ?? ?? 00 00 8C } 
        $x2 = { C6 84 24 ?? ?? 00 00 1A }  
        $x3 = { C6 84 24 ?? ?? 00 00 D4 } 
        $x4 = { C6 84 24 ?? ?? 00 00 03 }  
        $x5 = { C6 84 24 ?? ?? 00 00 B4 } 
        $x6 = { C6 84 24 ?? ?? 00 00 80 }
 
    condition:
        $mz at 0 and 
        ( ( all of ($hex*) and all of ($s*) ) or (all of ($x*)))
}
