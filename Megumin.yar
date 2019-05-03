rule Megumin : Megumin {
  meta:
    description = "Detecting Megumin v2"
    author = "Fumik0_"
    date = "2019-05-02"

  strings:
    $mz = {4D 5A}

    $s1 = "Megumin/2.0" wide ascii
    $s2 = "/cpu" wide ascii
    $s3 = "/task?hwid=" wide ascii
    $s4 = "/gate?hwid=" wide ascii
    $s5 = "/suicide" wide ascii

  condition:
    $mz at 0 and (all of ($s*))
}
