rule Arkei : Arkei
{
     meta:
          Author = "Fumik0_"
          Description = "Rule to detect Arkei"
          Date = "2018/12/11"

      strings:
          $mz = { 4D 5A }

          $s1 = "Arkei" wide ascii
          $s2 = "/server/gate" wide ascii
          $s3 = "/server/grubConfig" wide ascii
          $s4 = "\\files\\" wide ascii
          $s5 = "SQLite" wide ascii

          $x1 = "/c taskkill /im" wide ascii
          $x2 = "screenshot.jpg" wide ascii
          $x3 = "files\\passwords.txt" wide ascii
          $x4 = "http://ip-api.com/line/" wide ascii
          $x5 = "[Hardware]" wide ascii
          $x6 = "[Network]" wide ascii
          $x7 = "[Processes]" wide ascii

          $hx1 = { 56 00 69 00 64 00 61 00 72 00 2E 00 63 00 70 00 70 00 }


     condition:
          $mz at 0 and
          ( (all of ($s*)) or ((all of ($x*)) and not $hx1))
}
