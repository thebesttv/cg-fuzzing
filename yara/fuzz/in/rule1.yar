rule SimpleRule {
    strings:
        $a = "test"
    condition:
        $a
}
