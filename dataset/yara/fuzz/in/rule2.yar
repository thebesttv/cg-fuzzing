rule HexRule {
    strings:
        $hex = { 48 65 6C 6C 6F }
    condition:
        $hex
}
