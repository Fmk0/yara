rule SupremePlusPlus {
   meta:
     description = "Yara rule to detect Supreme++"
     author = "Fumik0_"
     date = "12/01/2019"

   strings:
     $mz = { 4D 5A }
    
     $s1 = "[Supreme Logger] Started" wide ascii
     $s2 = "&soft=supreme" wide ascii

   condition:
     $mz at 0 and all of ($s*)
}

