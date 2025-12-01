rule RegexRule {
    strings:
        $re = /test[0-9]+/
    condition:
        $re
}
