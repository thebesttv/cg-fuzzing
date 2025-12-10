proc add {a b} {
    return [expr {$a + $b}]
}
set result [add 3 4]
puts $result
