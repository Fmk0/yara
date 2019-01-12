rule Revenge 
{
    meta:
        description = "Yara rule for Revenge RAT"
        author = "Fumik0_"
        date = "12/01/2019" 

    strings:
        $mz   = { 4D 5A }

        $net1 = { 23 53 74 72 69 6E 67 73 }
        $net2 = { 23 47 55 49 44 }
        $net3 = { 23 42 6C 6F 62 }

        $hex1 = { 2D 00 5D 00 4E 00 4B 00 5B 00 2D }
        $hex2 = { 6E 00 65 00 77 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 4F 00 62 00 }
        $hex3 = { 6A 00 65 00 63 00 74 00 28 00 22 00 53 00 68 00 65 00 6C 00 6C 00 2E 00 41 00 }
        $hex4 = { 70 00 70 00 6C 00 69 00 63 00 61 00 74 00 69 00 6F 00 6E 00 22 00 29 }

    condition:
        $mz at 0 and ((all of ($net*)) and (all of ($hex*)))
}
