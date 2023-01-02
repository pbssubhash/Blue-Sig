rule creation_of_dmp {
    meta:
        author = "Subhash P <@pbssubhash>"
        filetype = "DUMP File"
        date = "1/1/2023"
        version = "1.0"
    strings:
        $md = { 4d 44 4d 50 }
        $a1 = "SeDebugPrivilege" fullword wide 
        $a2 = "\\pipe\\lsass" fullword wide
        $a3 = "lsasspirpc" fullword wide
    condition:
        ($md at 0) and all of ($a*)
}