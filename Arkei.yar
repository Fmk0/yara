rule Arkei : Arkei
{
   meta:
      Author = "Fumik0_"
      Description = "Rule to detect Arkei 9.?.?"
      Date = "2018/12/11"

   strings:
      $mz = { 4D 5A }

      $x1 = "/c taskkill /im" wide ascii
      $x2 = "screenshot.jpg" wide ascii
      $x3 = "files\\passwords.txt" wide ascii
      $x4 = "http://ip-api.com/line/" wide ascii
      $x5 = "[Hardware]" wide ascii
      $x6 = "[Network]" wide ascii
      $x7 = "[Processes]" wide ascii

   condition:
      $mz at 0 and (all of ($x*)) 
}
