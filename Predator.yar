rule Predator_The_Thief : Predator_The_Thief {
    meta:
        description = "Yara rule for Predator The Thief v2.3.1 to 3.0.6"
        author = "Fumik0_"
        date = "2018/10/12"
        update = "2019/01/01"

    strings:
        $mz = { 4D 5A }
         
        /*
            Predator v2
        */
        $hex1 = { BF 00 00 40 06 } 
        $hex2 = { C6 04 31 6B }
        $hex3 = { C6 04 31 63 }
        $hex4 = { C6 04 31 75 }
        $hex5 = { C6 04 31 66 }
 
        $s1 = "sqlite_" ascii wide
 
        /*
            Predator v3
        */
        $x1 = { C6 84 24 ?? ?? 00 00 8C } 
        $x2 = { C6 84 24 ?? ?? 00 00 1A }  
        $x3 = { C6 84 24 ?? ?? 00 00 D4 } 
        $x4 = { C6 84 24 ?? ?? 00 00 03 }  
        $x5 = { C6 84 24 ?? ?? 00 00 B4 } 
        $x6 = { C6 84 24 ?? ?? 00 00 80 }
        
        /*
            Predator V3.0.3 -> 3.0.6 
        */
        $y1 = { B8 00 E1 F5 05 }
        $y2 = { 89 5C 24 0C } 
        $y3 = { FF 44 24 ?? }
        $y4 = { 39 44 24 0C }  
        $y5 = { BF 00 00 A0 00 }


    condition:
        $mz at 0 and 
        ( 
             ( all of ($hex*) and all of ($s*) ) 
             or 
             ( all of ($x*))
             or 
             (all of ($y*)) 
        )
}
