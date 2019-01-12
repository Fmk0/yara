rule ImmortalStealer 
{
    meta:
        description = "Yara rule for Immortal Stealer"
        author = "Fumik0_"
        date = "12/01/2019" 

    strings:
        $mz   = { 4D 5A }

        $net1 = { 23 53 74 72 69 6E 67 73 }
        $net2 = { 23 47 55 49 44 }
        $net3 = { 23 42 6C 6F 62 }

        $hex1 = { 43 00 72 00 65 00 61 00 74 00 65 00 20 00 42 00 79 00 20 00 5A 00 65 00 74 00 35 00 44 }
        $hex2 = { 49 00 6D 00 6D 00 6F 00 72 00 74 00 61 00 6C 00 20 00 53 00 74 00 65 00 61 00 6C 00 65 00 72 }

    condition:
        $mz at 0 and ((all of ($net*)) and (all of ($hex*)))
}
