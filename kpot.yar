rule kpot {
    meta:
        description = "Kpot"
        type = "Stealer"
        author = "Fumik0_"
        date = "30/08/2018"

    strings:
        $mz = { 4d 5a }

        # Variant 1
        $v1_s1 = "GET %s HTTP/1.1" wide ascii
        $v1_s2 = "Host: %s" wide ascii
        $v1_s3 = "%02d-%02d-%02d %d:%02d:%02d" wide ascii
        $v1_s4 = "%S/base64.php?_f=%S" wide ascii      
        $v1_s5 = "IP: %S" wide ascii
        $v1_s6 = "MachineGuid: %s" wide ascii
        $v1_s7 = "CPU: %S (%d cores)" wide ascii
        $v1_s8 = "RAM: %S MB" wide ascii
        $v1_s9 = "Screen: %dx%d" wide ascii
        $v1_s10 = "PC: %s" wide ascii
        $v1_s11 = "User: %s" wide ascii
        $v1_s12 = "LT: %S (UTC+%d:%d)" wide ascii
        $v1_s13 = "GPU:" wide ascii
        $v1_s14 = "regbot.php" wide ascii
        $v1_s15 = "ip.php" wide ascii

        # Variant 2
        $v2_s1 = "GET %s HTTP/1.1" wide ascii
        $v2_s2 = "%s/%s.php" wide ascii
        $v2_s3 = "%s/gate.php" wide ascii
        $v2_s4 = "RAM: %s MB" wide ascii
        $v2_s5 = "IP: %s" wide ascii
        $v2_s6 = "CPU: %s (%d cores)" wide ascii
        $v2_s7 = "RAM: %s MB" wide ascii
        $v2_s8 = "Screen: %dx%d" wide ascii
        $v2_s9 = "LT: %s (UTC+%d:%d)" wide ascii
        $v2_s10 = "GPU:" wide ascii
        $v2_s11 = "screen.png" wide ascii

    condition:
        ($mz at 0) and ( (all of ($v1_*)) or (all of ($v2_*)) )
}
