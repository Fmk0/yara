rule ProtonBot : ProtonBot {
    meta:
        description = "Detecting ProtonBot v1"
        author = "Fumik0_"
        date = "2019-05-24"

    strings:
        $mz = {4D 5A}

        $s1 = "proton bot" wide ascii
        $s2 = "Build.pdb" wide ascii
        $s3 = "ktmw32.dll" wide ascii
        $s4 = "json.hpp" wide ascii

    condition:
        $mz at 0 and (all of ($s*))
}
