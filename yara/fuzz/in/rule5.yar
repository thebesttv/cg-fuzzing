rule ComplexCondition {
    strings:
        $a = "test1"
        $b = "test2"
    condition:
        $a and $b
}
