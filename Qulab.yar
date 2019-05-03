rule Qulab_Stealer : Qulab 
{
   meta:
      description = "Yara rule for detecting Qulab (In memory only)"
      author = "Fumik0_"

   strings:
      $s1 = "QULAB CLIPPER + STEALER" wide ascii
      $s2 = "SDA" wide ascii
      $s3 = "SELECT * FROM Win32_VideoController" wide ascii
      $s4 = "maFile" wide ascii
      $s5 = "Exodus" wide ascii
   
   condition:
      all of ($s*)
}
