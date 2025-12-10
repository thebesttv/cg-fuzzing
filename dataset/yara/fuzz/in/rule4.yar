rule MetaRule {
    meta:
        author = "test"
        description = "test rule"
    strings:
        $a = "test"
    condition:
        $a
}
