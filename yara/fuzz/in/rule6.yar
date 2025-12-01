rule WildcardHex {
    strings:
        $h = { 48 ?? 6C [2-4] 6F }
    condition:
        $h
}
