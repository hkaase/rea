.text
.global probe_entry
probe_entry:
    mflr 0
    stw 0, 4(1)
    bl probe_helper
    lwz 0, 4(1)
    mtlr 0
    blr
    nop
    nop
probe_helper:
    li 3, 7
    blr
