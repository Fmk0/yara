rule Rarog : Rarog {
   meta:
        description = "Yara rule to detect Rarog 7.0"
        author = "Fumik0_"
        date = "2018/12/09"
   strings:
        $s1 = "CPUMinerThread - Delay" wide ascii
        $s2 = "DownloadGPUMiner - Decode files list..." wide ascii
        $s3 = "Rarog - GPU module active, start GPUMinerThread()" wide ascii
        $s4 = "[Rarog Logger] Started" wide ascii
 
   condition:
         all of them
}
