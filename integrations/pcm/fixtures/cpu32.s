.text
.global probe_entry
probe_entry:
    jsr probe_helper
    rts
.org 0x10
probe_helper:
    moveq #7, %d0
    rts
.org 0x20
probe_table:
    lea probe_values, %a0
    tblu.b (%a0), %d0
    rts
.org 0x40
probe_values:
    .byte 0, 16, 32, 64
