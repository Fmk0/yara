rule StarStealer {
   meta:
     description = "Yara rule to detect StarStealer"
     author = "Fumik0_"
     date = "2019/05/09"

   strings:
     $mz = { 4D 5A }
    
     $s1 = "ScreenShot.png" wide ascii
     $s2 = "CreditCards.png" wide ascii
     $s3 = "UserAgents.txt" wide ascii
     $s4 = "StarStealer by F A T H E R" wide ascii

   condition:
     $mz at 0 and all of ($s*)
}
