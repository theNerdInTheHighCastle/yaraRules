rule contiYara {

    meta:
        last_updated = "2022-09-16"
        author = "thenerdinthehighcastle"
        description = "a simple Yara rule to carve out juicy elements from Conti malware"
        sha256 = "004ede55a972e10d9a21bcf338b4907d6eed65bf5ad6abbbd5aec7d8484bdedf"

    strings:
    // fill out identifying strings and other criteria
        $string1 = "Advapi32.dll" fullword ascii //call for API
        $string2 = "Shlwapi.dll" fullword ascii //
        $string3 = "Rstrtmgr.dll" fullword ascii
        $string4 = "Iphlpapi.dll" fullword ascii
        $string5 = "User32.dll" fullword ascii
        $string6 = "Kernel32.dll" fullword ascii
        $string7 = "Netapi32.dll" fullword ascii
        $string8 = "SHELL32.dll" fullword ascii
        $string9 = "Ws2_32.dll" fullword ascii
        $PE_magic_byte = "MZ"
        // $sus_hex_string = { }

    condition:
        // fill out the condition that must be met to find the binary
       any of them 
}