FDE function: 0x1294c4 .. 0x12a7b0 size 0x12ec
0x1294c4  cbnz     w8, #0x100318
0x1294c8  add      x28, x20, w0, uxtw #3
0x1294cc  ldr      x0, [x28, #0x20]!
0x1294d0  bl       #0x1472e8   ; -> None
0x1294d4  mov      w22, w0
0x1294d8  mov      w23, wzr
0x1294dc  cmp      w22, w23
0x1294e0  b.eq     #0x12a8d4
0x1294e4  ldr      x0, [x28]
0x1294e8  mov      w1, w23
0x1294ec  ldr      x24, [x26]
0x1294f0  add      w25, w21, w23
0x1294f4  bl       #0x147304   ; -> None
0x1294f8  mov      w3, w0
0x1294fc  mov      x0, x19
0x129500  mov      x1, x24
0x129504  mov      w2, w25
0x129508  bl       #0x146ed8   ; -> None
0x12950c  ldp      x24, x25, [sp, #8]
0x129510  add      w23, w23, #1
0x129514  ldr      w8, [x19]
0x129518  cbz      w8, #0x1294dc
0x12951c  b        #0x100318
0x129520  ldp      x24, x25, [sp, #8]
0x129524  cmp      w0, #0x143
0x129528  b.ne     #0x12a8b4
0x12952c  ldr      x1, [x20]
0x129530  mov      x0, x19
0x129534  mov      w2, #9
0x129538  bl       #0x147630   ; -> None
0x12953c  ldr      w8, [x19]
0x129540  cbnz     w8, #0x100318
0x129544  ldr      x1, [x20]
0x129548  mov      x0, x19
0x12954c  bl       #0x147734   ; -> None
0x129550  ldr      w8, [x19]
0x129554  cbnz     w8, #0x100318
0x129558  mov      w21, w0
0x12955c  ldr      x1, [x20]
0x129560  mov      x0, x19
0x129564  bl       #0x147734   ; -> None
0x129568  ldr      w8, [x19]
0x12956c  cbnz     w8, #0x100318
0x129570  mov      w3, w0
0x129574  ldr      x1, [x26]
0x129578  mov      x0, x19
0x12957c  mov      w2, w21
0x129580  bl       #0x146ed8   ; -> None
0x129584  ldr      w8, [x19]
0x129588  cbnz     w8, #0x100318
0x12958c  ldr      x1, [x20]
0x129590  mov      x0, x19
0x129594  mov      w2, #5
0x129598  bl       #0x147630   ; -> None
0x12959c  ldr      w8, [x19]
0x1295a0  cbnz     w8, #0x100318
0x1295a4  ldr      x1, [x20]
0x1295a8  mov      x0, x19
0x1295ac  mov      w2, #9
0x1295b0  bl       #0x147630   ; -> None
0x1295b4  ldr      w8, [x19]
0x1295b8  cbnz     w8, #0x100318
0x1295bc  ldr      x1, [x20]
0x1295c0  mov      x0, x19
0x1295c4  bl       #0x147734   ; -> None
0x1295c8  ldr      w8, [x19]
0x1295cc  cbnz     w8, #0x100318
0x1295d0  mov      w1, w0
0x1295d4  ldp      x21, x0, [x20]
0x1295d8  bl       #0x147304   ; -> None
0x1295dc  mov      w2, w0
0x1295e0  mov      x0, x19
0x1295e4  mov      x1, x21
0x1295e8  bl       #0x147630   ; -> None
0x1295ec  ldr      w8, [x19]
0x1295f0  cbnz     w8, #0x100318
0x1295f4  ldr      x1, [x20]
0x1295f8  mov      x0, x19
0x1295fc  bl       #0x147734   ; -> None
0x129600  ldr      w8, [x19]
0x129604  cbnz     w8, #0x100318
0x129608  mov      w21, w0
0x12960c  ldr      x1, [x20]
0x129610  mov      x0, x19
0x129614  bl       #0x147734   ; -> None
0x129618  ldr      w8, [x19]
0x12961c  cbnz     w8, #0x100318
0x129620  add      x28, x20, w0, uxtw #3
0x129624  ldr      x0, [x28, #0x20]!
0x129628  bl       #0x1472e8   ; -> None
0x12962c  mov      w22, w0
0x129630  mov      w23, wzr
0x129634  cmp      w22, w23
0x129638  b.eq     #0x12a900
0x12963c  ldr      x0, [x28]
0x129640  mov      w1, w23
0x129644  ldr      x24, [x26]
0x129648  add      w25, w21, w23
0x12964c  bl       #0x147304   ; -> None
0x129650  mov      w3, w0
0x129654  mov      x0, x19
0x129658  mov      x1, x24
0x12965c  mov      w2, w25
0x129660  bl       #0x146ed8   ; -> None
0x129664  ldp      x24, x25, [sp, #8]
0x129668  add      w23, w23, #1
0x12966c  ldr      w8, [x19]
0x129670  cbz      w8, #0x129634
0x129674  b        #0x100318
0x129678  ldp      x24, x25, [sp, #8]
0x12967c  cmp      w0, #0x29f
0x129680  b.ne     #0x12a8b4
0x129684  ldr      x1, [x20]
0x129688  mov      x0, x19
0x12968c  mov      w2, #0x14
0x129690  bl       #0x147630   ; -> None
0x129694  ldr      w8, [x19]
0x129698  cbnz     w8, #0x100318
0x12969c  ldr      x1, [x20]
0x1296a0  mov      x0, x19
0x1296a4  bl       #0x147734   ; -> None
0x1296a8  ldr      w8, [x19]
0x1296ac  cbnz     w8, #0x100318
0x1296b0  mov      w21, w0
0x1296b4  ldr      x1, [x20]
0x1296b8  mov      x0, x19
0x1296bc  bl       #0x147734   ; -> None
0x1296c0  ldr      w8, [x19]
0x1296c4  cbnz     w8, #0x100318
0x1296c8  mov      w3, w0
0x1296cc  ldr      x1, [x26]
0x1296d0  mov      x0, x19
0x1296d4  mov      w2, w21
0x1296d8  bl       #0x146ed8   ; -> None
0x1296dc  ldr      w8, [x19]
0x1296e0  cbnz     w8, #0x100318
0x1296e4  ldr      x1, [x20]
0x1296e8  mov      x0, x19
0x1296ec  mov      w2, #0x72
0x1296f0  bl       #0x147630   ; -> None
0x1296f4  ldr      w8, [x19]
0x1296f8  cbnz     w8, #0x100318
0x1296fc  ldr      x1, [x20]
0x129700  mov      x0, x19
0x129704  mov      w2, #2
0x129708  bl       #0x147630   ; -> None
0x12970c  ldr      w8, [x19]
0x129710  cbnz     w8, #0x100318
0x129714  ldr      x1, [x20]
0x129718  mov      x0, x19
0x12971c  bl       #0x147734   ; -> None
0x129720  ldr      w8, [x19]
0x129724  cbnz     w8, #0x100318
0x129728  mov      w1, w0
0x12972c  ldp      x21, x0, [x20]
0x129730  bl       #0x147304   ; -> None
0x129734  mov      w2, w0
0x129738  mov      x0, x19
0x12973c  mov      x1, x21
0x129740  bl       #0x147630   ; -> None
0x129744  ldr      w8, [x19]
0x129748  cbnz     w8, #0x100318
0x12974c  ldr      x1, [x20]
0x129750  mov      x0, x19
0x129754  bl       #0x147734   ; -> None
0x129758  ldr      w8, [x19]
0x12975c  cbnz     w8, #0x100318
0x129760  mov      w1, w0
0x129764  ldp      x21, x0, [x20]
0x129768  bl       #0x147304   ; -> None
0x12976c  mov      w2, w0
0x129770  mov      x0, x19
0x129774  mov      x1, x21
0x129778  bl       #0x147630   ; -> None
0x12977c  ldr      w8, [x19]
0x129780  cbnz     w8, #0x100318
0x129784  ldr      x1, [x20]
0x129788  mov      x0, x19
0x12978c  bl       #0x147734   ; -> None
0x129790  ldr      w8, [x19]
0x129794  cbnz     w8, #0x100318
0x129798  mov      w21, w0
0x12979c  ldr      x1, [x20]
0x1297a0  mov      x0, x19
0x1297a4  bl       #0x147734   ; -> None
0x1297a8  ldr      w8, [x19]
0x1297ac  cbnz     w8, #0x100318
0x1297b0  ldr      x1, [x20]
0x1297b4  add      w2, w0, w21
0x1297b8  mov      x0, x19
0x1297bc  bl       #0x147630   ; -> None
0x1297c0  ldr      w8, [x19]
0x1297c4  cbnz     w8, #0x100318
0x1297c8  ldr      x1, [x20]
0x1297cc  mov      x0, x19
0x1297d0  mov      w2, #0x14
0x1297d4  bl       #0x147630   ; -> None
0x1297d8  ldr      w8, [x19]
0x1297dc  cbnz     w8, #0x100318
0x1297e0  ldr      x1, [x20]
0x1297e4  mov      x0, x19
0x1297e8  bl       #0x147734   ; -> None
0x1297ec  ldr      w8, [x19]
0x1297f0  cbnz     w8, #0x100318
0x1297f4  mov      w1, w0
0x1297f8  ldp      x21, x0, [x20]
0x1297fc  bl       #0x147304   ; -> None
0x129800  mov      w2, w0
0x129804  mov      x0, x19
0x129808  mov      x1, x21
0x12980c  bl       #0x147630   ; -> None
0x129810  ldr      w8, [x19]
0x129814  cbnz     w8, #0x100318
0x129818  ldr      x1, [x20]
0x12981c  mov      x0, x19
0x129820  bl       #0x147734   ; -> None
0x129824  ldr      w8, [x19]
0x129828  cbnz     w8, #0x100318
0x12982c  mov      w21, w0
0x129830  ldr      x1, [x20]
0x129834  mov      x0, x19
0x129838  bl       #0x147734   ; -> None
0x12983c  ldr      w8, [x19]
0x129840  cbnz     w8, #0x100318
0x129844  mov      w3, w0
0x129848  ldr      x1, [x26]
0x12984c  mov      x0, x19
0x129850  mov      w2, w21
0x129854  bl       #0x146ed8   ; -> None
0x129858  ldr      w8, [x19]
0x12985c  cbnz     w8, #0x100318
0x129860  ldr      x1, [x20]
0x129864  mov      x0, x19
0x129868  mov      w2, #1
0x12986c  bl       #0x147630   ; -> None
0x129870  ldr      w8, [x19]
0x129874  cbnz     w8, #0x100318
0x129878  ldr      x8, [sp, #0x18]
0x12987c  mov      x0, x19
0x129880  mov      w2, #0x2c3
0x129884  b        #0x12a8c0
0x129888  ldp      x24, x25, [sp, #8]
0x12988c  cmp      w0, #0x319
0x129890  b.ne     #0x12a8b4
0x129894  ldr      x1, [x20]
0x129898  mov      x0, x19
0x12989c  mov      w2, #0x16
0x1298a0  bl       #0x147630   ; -> None
0x1298a4  ldr      w8, [x19]
0x1298a8  cbnz     w8, #0x100318
0x1298ac  ldr      x1, [x20]
0x1298b0  mov      x0, x19
0x1298b4  bl       #0x147734   ; -> None
0x1298b8  ldr      w8, [x19]
0x1298bc  cbnz     w8, #0x100318
0x1298c0  mov      w21, w0
0x1298c4  ldr      x1, [x20]
0x1298c8  mov      x0, x19
0x1298cc  bl       #0x147734   ; -> None
0x1298d0  ldr      w8, [x19]
0x1298d4  cbnz     w8, #0x100318
0x1298d8  mov      w3, w0
0x1298dc  ldr      x1, [x26]
0x1298e0  mov      x0, x19
0x1298e4  mov      w2, w21
0x1298e8  bl       #0x146ed8   ; -> None
0x1298ec  ldr      w8, [x19]
0x1298f0  cbnz     w8, #0x100318
0x1298f4  ldr      x1, [x20]
0x1298f8  mov      x0, x19
0x1298fc  mov      w2, #1
0x129900  bl       #0x147630   ; -> None
0x129904  ldr      w8, [x19]
0x129908  cbnz     w8, #0x100318
0x12990c  ldr      x8, [sp, #0x18]
0x129910  mov      x0, x19
0x129914  mov      w2, #0x329
0x129918  b        #0x12a8c0
0x12991c  ldp      x24, x25, [sp, #8]
0x129920  cmp      w0, #0x19f
0x129924  b.ne     #0x12a8b4
0x129928  ldr      x1, [x20]
0x12992c  mov      x0, x19
0x129930  mov      w2, #0xc
0x129934  bl       #0x147630   ; -> None
0x129938  ldr      w8, [x19]
0x12993c  cbnz     w8, #0x100318
0x129940  ldr      x1, [x20]
0x129944  mov      x0, x19
0x129948  bl       #0x147734   ; -> None
0x12994c  ldr      w8, [x19]
0x129950  cbnz     w8, #0x100318
0x129954  mov      w21, w0
0x129958  ldr      x1, [x20]
0x12995c  mov      x0, x19
0x129960  bl       #0x147734   ; -> None
0x129964  ldr      w8, [x19]
0x129968  cbnz     w8, #0x100318
0x12996c  mov      w3, w0
0x129970  ldr      x1, [x26]
0x129974  mov      x0, x19
0x129978  mov      w2, w21
0x12997c  bl       #0x146ed8   ; -> None
0x129980  ldr      w8, [x19]
0x129984  cbnz     w8, #0x100318
0x129988  ldr      x1, [x20]
0x12998c  mov      x0, x19
0x129990  mov      w2, #7
0x129994  bl       #0x147630   ; -> None
0x129998  ldr      w8, [x19]
0x12999c  cbnz     w8, #0x100318
0x1299a0  ldr      x1, [x20]
0x1299a4  mov      x0, x19
0x1299a8  mov      w2, #0xc
0x1299ac  bl       #0x147630   ; -> None
0x1299b0  ldr      w8, [x19]
0x1299b4  cbnz     w8, #0x100318
0x1299b8  ldr      x1, [x20]
0x1299bc  mov      x0, x19
0x1299c0  bl       #0x147734   ; -> None
0x1299c4  ldr      w8, [x19]
0x1299c8  cbnz     w8, #0x100318
0x1299cc  mov      w1, w0
0x1299d0  ldp      x21, x0, [x20]
0x1299d4  bl       #0x147304   ; -> None
0x1299d8  mov      w2, w0
0x1299dc  mov      x0, x19
0x1299e0  mov      x1, x21
0x1299e4  bl       #0x147630   ; -> None
0x1299e8  ldr      w8, [x19]
0x1299ec  cbnz     w8, #0x100318
0x1299f0  ldr      x1, [x20]
0x1299f4  mov      x0, x19
0x1299f8  bl       #0x147734   ; -> None
0x1299fc  ldr      w8, [x19]
0x129a00  cbnz     w8, #0x100318
0x129a04  mov      w21, w0
0x129a08  ldr      x1, [x20]
0x129a0c  mov      x0, x19
0x129a10  bl       #0x147734   ; -> None
0x129a14  ldr      w8, [x19]
0x129a18  cbnz     w8, #0x100318
0x129a1c  add      x28, x20, w0, uxtw #3
0x129a20  ldr      x0, [x28, #0x20]!
0x129a24  bl       #0x1472e8   ; -> None
0x129a28  mov      w22, w0
0x129a2c  mov      w23, wzr
0x129a30  cmp      w22, w23
0x129a34  b.eq     #0x12a92c
0x129a38  ldr      x0, [x28]
0x129a3c  mov      w1, w23
0x129a40  ldr      x24, [x26]
0x129a44  add      w25, w21, w23
0x129a48  bl       #0x147304   ; -> None
0x129a4c  mov      w3, w0
0x129a50  mov      x0, x19
0x129a54  mov      x1, x24
0x129a58  mov      w2, w25
0x129a5c  bl       #0x146ed8   ; -> None
0x129a60  ldp      x24, x25, [sp, #8]
0x129a64  add      w23, w23, #1
0x129a68  ldr      w8, [x19]
0x129a6c  cbz      w8, #0x129a30
0x129a70  b        #0x100318
0x129a74  ldp      x24, x25, [sp, #8]
0x129a78  b.ne     #0x12a8b4
0x129a7c  ldr      x1, [x20]
0x129a80  mov      x0, x19
0x129a84  mov      w2, #8
0x129a88  bl       #0x147630   ; -> None
0x129a8c  ldr      w8, [x19]
0x129a90  cbnz     w8, #0x100318
0x129a94  ldr      x8, [sp, #0x18]
0x129a98  mov      x0, x19
0x129a9c  mov      w2, #0x10b
0x129aa0  b        #0x12a8c0
0x129aa4  ldp      x24, x25, [sp, #8]
0x129aa8  b.ne     #0x12a8b4
0x129aac  ldr      x1, [x20]
0x129ab0  mov      x0, x19
0x129ab4  mov      w2, #8
0x129ab8  bl       #0x147630   ; -> None
0x129abc  ldr      w8, [x19]
0x129ac0  cbnz     w8, #0x100318
0x129ac4  ldr      x1, [x20]
0x129ac8  mov      x0, x19
0x129acc  bl       #0x147734   ; -> None
0x129ad0  ldr      w8, [x19]
0x129ad4  cbnz     w8, #0x100318
0x129ad8  mov      w21, w0
0x129adc  ldr      x1, [x20]
0x129ae0  mov      x0, x19
0x129ae4  bl       #0x147734   ; -> None
0x129ae8  ldr      w8, [x19]
0x129aec  cbnz     w8, #0x100318
0x129af0  mov      w3, w0
0x129af4  ldr      x1, [x26]
0x129af8  mov      x0, x19
0x129afc  mov      w2, w21
0x129b00  bl       #0x146ed8   ; -> None
0x129b04  ldr      w8, [x19]
0x129b08  cbnz     w8, #0x100318
0x129b0c  ldr      x1, [x20]
0x129b10  mov      x0, x19
0x129b14  mov      w2, #4
0x129b18  bl       #0x147630   ; -> None
0x129b1c  ldr      w8, [x19]
0x129b20  cbnz     w8, #0x100318
0x129b24  ldr      x1, [x20]
0x129b28  mov      x0, x19
0x129b2c  mov      w2, #8
0x129b30  bl       #0x147630   ; -> None
0x129b34  ldr      w8, [x19]
0x129b38  cbnz     w8, #0x100318
0x129b3c  ldr      x1, [x20]
0x129b40  mov      x0, x19
0x129b44  bl       #0x147734   ; -> None
0x129b48  ldr      w8, [x19]
0x129b4c  cbnz     w8, #0x100318
0x129b50  mov      w1, w0
0x129b54  ldp      x21, x0, [x20]
0x129b58  bl       #0x147304   ; -> None
0x129b5c  mov      w2, w0
0x129b60  mov      x0, x19
0x129b64  mov      x1, x21
0x129b68  bl       #0x147630   ; -> None
0x129b6c  ldr      w8, [x19]
0x129b70  cbnz     w8, #0x100318
0x129b74  ldr      x1, [x20]
0x129b78  mov      x0, x19
0x129b7c  bl       #0x147734   ; -> None
0x129b80  ldr      w8, [x19]
0x129b84  cbnz     w8, #0x100318
0x129b88  mov      w21, w0
0x129b8c  ldr      x1, [x20]
0x129b90  mov      x0, x19
0x129b94  bl       #0x147734   ; -> None
0x129b98  ldr      w8, [x19]
0x129b9c  cbnz     w8, #0x100318
0x129ba0  add      x28, x20, w0, uxtw #3
0x129ba4  ldr      x0, [x28, #0x20]!
0x129ba8  bl       #0x1472e8   ; -> None
0x129bac  mov      w22, w0
0x129bb0  mov      w23, wzr
0x129bb4  cmp      w22, w23
0x129bb8  b.eq     #0x12a984
0x129bbc  ldr      x0, [x28]
0x129bc0  mov      w1, w23
0x129bc4  ldr      x24, [x26]
0x129bc8  add      w25, w21, w23
0x129bcc  bl       #0x147304   ; -> None
0x129bd0  mov      w3, w0
0x129bd4  mov      x0, x19
0x129bd8  mov      x1, x24
0x129bdc  mov      w2, w25
0x129be0  bl       #0x146ed8   ; -> None
0x129be4  ldp      x24, x25, [sp, #8]
0x129be8  add      w23, w23, #1
0x129bec  ldr      w8, [x19]
0x129bf0  cbz      w8, #0x129bb4
0x129bf4  b        #0x100318
0x129bf8  ldp      x24, x25, [sp, #8]
0x129bfc  b.ne     #0x12a8b4
0x129c00  ldr      x1, [x20]
0x129c04  mov      x0, x19
0x129c08  mov      w2, #0x10
0x129c0c  bl       #0x147630   ; -> None
0x129c10  ldr      w8, [x19]
0x129c14  cbnz     w8, #0x100318
0x129c18  ldr      x1, [x20]
0x129c1c  mov      x0, x19
0x129c20  bl       #0x147734   ; -> None
0x129c24  ldr      w8, [x19]
0x129c28  cbnz     w8, #0x100318
0x129c2c  mov      w21, w0
0x129c30  ldr      x1, [x20]
0x129c34  mov      x0, x19
0x129c38  bl       #0x147734   ; -> None
0x129c3c  ldr      w8, [x19]
0x129c40  cbnz     w8, #0x100318
0x129c44  mov      w3, w0
0x129c48  ldr      x1, [x26]
0x129c4c  mov      x0, x19
0x129c50  mov      w2, w21
0x129c54  bl       #0x146ed8   ; -> None
0x129c58  ldr      w8, [x19]
0x129c5c  cbnz     w8, #0x100318
0x129c60  ldr      x1, [x20]
0x129c64  mov      x0, x19
0x129c68  mov      w2, #1
0x129c6c  bl       #0x147630   ; -> None
0x129c70  ldr      w8, [x19]
0x129c74  cbnz     w8, #0x100318
0x129c78  ldr      x8, [sp, #0x18]
0x129c7c  mov      x0, x19
0x129c80  mov      w2, #0x29f
0x129c84  b        #0x12a8c0
0x129c88  ldp      x24, x25, [sp, #8]
0x129c8c  b.ne     #0x12a8b4
0x129c90  ldr      x1, [x20]
0x129c94  mov      x0, x19
0x129c98  mov      w2, #0x11
0x129c9c  bl       #0x147630   ; -> None
0x129ca0  ldr      w8, [x19]
0x129ca4  cbnz     w8, #0x100318
0x129ca8  ldr      x1, [x20]
0x129cac  mov      x0, x19
0x129cb0  bl       #0x147734   ; -> None
0x129cb4  ldr      w8, [x19]
0x129cb8  cbnz     w8, #0x100318
0x129cbc  mov      w21, w0
0x129cc0  ldr      x1, [x20]
0x129cc4  mov      x0, x19
0x129cc8  bl       #0x147734   ; -> None
0x129ccc  ldr      w8, [x19]
0x129cd0  cbnz     w8, #0x100318
0x129cd4  mov      w3, w0
0x129cd8  ldr      x1, [x26]
0x129cdc  mov      x0, x19
0x129ce0  mov      w2, w21
0x129ce4  bl       #0x146ed8   ; -> None
0x129ce8  ldr      w8, [x19]
0x129cec  cbnz     w8, #0x100318
0x129cf0  ldr      x1, [x20]
0x129cf4  mov      x0, x19
0x129cf8  mov      w2, #0x14
0x129cfc  bl       #0x147630   ; -> None
0x129d00  ldr      w8, [x19]
0x129d04  cbnz     w8, #0x100318
0x129d08  ldr      x1, [x20]
0x129d0c  mov      x0, x19
0x129d10  mov      w2, #4
0x129d14  bl       #0x147630   ; -> None
0x129d18  ldr      w8, [x19]
0x129d1c  cbnz     w8, #0x100318
0x129d20  ldr      x1, [x20]
0x129d24  mov      x0, x19
0x129d28  mov      w2, #8
0x129d2c  bl       #0x147630   ; -> None
0x129d30  ldr      w8, [x19]
0x129d34  cbnz     w8, #0x100318
0x129d38  ldr      x1, [x20]
0x129d3c  mov      x0, x19
0x129d40  mov      w2, #2
0x129d44  bl       #0x147630   ; -> None
0x129d48  ldr      w8, [x19]
0x129d4c  cbnz     w8, #0x100318
0x129d50  ldr      x1, [x20]
0x129d54  mov      x0, x19
0x129d58  mov      w2, #2
0x129d5c  bl       #0x147630   ; -> None
0x129d60  ldr      w8, [x19]
0x129d64  cbnz     w8, #0x100318
0x129d68  ldr      x1, [x20]
0x129d6c  mov      x0, x19
0x129d70  bl       #0x147734   ; -> None
0x129d74  ldr      w8, [x19]
0x129d78  cbnz     w8, #0x100318
0x129d7c  mov      w1, w0
0x129d80  ldp      x21, x0, [x20]
0x129d84  bl       #0x147304   ; -> None
0x129d88  mov      w2, w0
0x129d8c  mov      x0, x19
0x129d90  mov      x1, x21
0x129d94  bl       #0x147630   ; -> None
0x129d98  ldr      w8, [x19]
0x129d9c  cbnz     w8, #0x100318
0x129da0  ldr      x1, [x20]
0x129da4  mov      x0, x19
0x129da8  bl       #0x147734   ; -> None
0x129dac  ldr      w8, [x19]
0x129db0  cbnz     w8, #0x100318
0x129db4  mov      w1, w0
0x129db8  ldp      x21, x0, [x20]
0x129dbc  bl       #0x147304   ; -> None
0x129dc0  mov      w2, w0
0x129dc4  mov      x0, x19
0x129dc8  mov      x1, x21
0x129dcc  bl       #0x147630   ; -> None
0x129dd0  ldr      w8, [x19]
0x129dd4  cbnz     w8, #0x100318
0x129dd8  ldr      x1, [x20]
0x129ddc  mov      x0, x19
0x129de0  mov      w2, #9
0x129de4  bl       #0x147630   ; -> None
0x129de8  ldr      w8, [x19]
0x129dec  cbnz     w8, #0x100318
0x129df0  ldr      x1, [x20]
0x129df4  mov      x0, x19
0x129df8  bl       #0x147734   ; -> None
0x129dfc  ldr      w8, [x19]
0x129e00  cbnz     w8, #0x100318
0x129e04  mov      w1, w0
0x129e08  ldp      x21, x0, [x20]
0x129e0c  bl       #0x147304   ; -> None
0x129e10  mov      w2, w0
0x129e14  mov      x0, x19
0x129e18  mov      x1, x21
0x129e1c  bl       #0x147630   ; -> None
0x129e20  ldr      w8, [x19]
0x129e24  cbnz     w8, #0x100318
0x129e28  ldr      x1, [x20]
0x129e2c  mov      x0, x19
0x129e30  bl       #0x147734   ; -> None
0x129e34  ldr      w8, [x19]
0x129e38  cbnz     w8, #0x100318
0x129e3c  mov      w1, w0
0x129e40  ldp      x21, x0, [x20]
0x129e44  bl       #0x147304   ; -> None
0x129e48  mov      w2, w0
0x129e4c  mov      x0, x19
0x129e50  mov      x1, x21
0x129e54  bl       #0x147630   ; -> None
0x129e58  ldr      w8, [x19]
0x129e5c  cbnz     w8, #0x100318
0x129e60  ldr      x1, [x20]
0x129e64  mov      x0, x19
0x129e68  mov      w2, #0x10
0x129e6c  bl       #0x147630   ; -> None
0x129e70  ldr      w8, [x19]
0x129e74  cbnz     w8, #0x100318
0x129e78  ldr      x1, [x20]
0x129e7c  mov      x0, x19
0x129e80  mov      w2, #1
0x129e84  bl       #0x147630   ; -> None
0x129e88  ldr      w8, [x19]
0x129e8c  cbnz     w8, #0x100318
0x129e90  ldr      x1, [x20]
0x129e94  mov      x0, x19
0x129e98  bl       #0x147734   ; -> None
0x129e9c  ldr      w8, [x19]
0x129ea0  cbnz     w8, #0x100318
0x129ea4  mov      w21, w0
0x129ea8  ldr      x1, [x20]
0x129eac  mov      x0, x19
0x129eb0  bl       #0x147734   ; -> None
0x129eb4  ldr      w8, [x19]
0x129eb8  cbnz     w8, #0x100318
0x129ebc  ldr      x1, [x20]
0x129ec0  add      w2, w0, w21
0x129ec4  mov      x0, x19
0x129ec8  bl       #0x147630   ; -> None
0x129ecc  ldr      w8, [x19]
0x129ed0  cbnz     w8, #0x100318
0x129ed4  ldr      x1, [x20]
0x129ed8  mov      x0, x19
0x129edc  bl       #0x147734   ; -> None
0x129ee0  ldr      w8, [x19]
0x129ee4  cbnz     w8, #0x100318
0x129ee8  mov      w21, w0
0x129eec  ldr      x1, [x20]
0x129ef0  mov      x0, x19
0x129ef4  bl       #0x147734   ; -> None
0x129ef8  ldr      w8, [x19]
0x129efc  cbnz     w8, #0x100318
0x129f00  ldr      x1, [x20]
0x129f04  add      w2, w0, w21
0x129f08  mov      x0, x19
0x129f0c  bl       #0x147630   ; -> None
0x129f10  ldr      w8, [x19]
0x129f14  cbnz     w8, #0x100318
0x129f18  ldr      x1, [x20]
0x129f1c  mov      x0, x19
0x129f20  bl       #0x147734   ; -> None
0x129f24  ldr      w8, [x19]
0x129f28  cbnz     w8, #0x100318
0x129f2c  mov      w21, w0
0x129f30  ldr      x1, [x20]
0x129f34  mov      x0, x19
0x129f38  bl       #0x147734   ; -> None
0x129f3c  ldr      w8, [x19]
0x129f40  cbnz     w8, #0x100318
0x129f44  ldr      x1, [x20]
0x129f48  add      w2, w0, w21
0x129f4c  mov      x0, x19
0x129f50  bl       #0x147630   ; -> None
0x129f54  ldr      w8, [x19]
0x129f58  cbnz     w8, #0x100318
0x129f5c  ldr      x1, [x20]
0x129f60  mov      x0, x19
0x129f64  bl       #0x147734   ; -> None
0x129f68  ldr      w8, [x19]
0x129f6c  cbnz     w8, #0x100318
0x129f70  mov      w21, w0
0x129f74  ldr      x1, [x20]
0x129f78  mov      x0, x19
0x129f7c  bl       #0x147734   ; -> None
0x129f80  ldr      w8, [x19]
0x129f84  cbnz     w8, #0x100318
0x129f88  ldr      x1, [x20]
0x129f8c  add      w2, w0, w21
0x129f90  mov      x0, x19
0x129f94  bl       #0x147630   ; -> None
0x129f98  ldr      w8, [x19]
0x129f9c  cbnz     w8, #0x100318
0x129fa0  ldr      x1, [x20]
0x129fa4  mov      x0, x19
0x129fa8  bl       #0x147734   ; -> None
0x129fac  ldr      w8, [x19]
0x129fb0  cbnz     w8, #0x100318
0x129fb4  mov      w21, w0
0x129fb8  ldr      x1, [x20]
0x129fbc  mov      x0, x19
0x129fc0  bl       #0x147734   ; -> None
0x129fc4  ldr      w8, [x19]
0x129fc8  cbnz     w8, #0x100318
0x129fcc  ldr      x1, [x20]
0x129fd0  add      w2, w0, w21
0x129fd4  mov      x0, x19
0x129fd8  bl       #0x147630   ; -> None
0x129fdc  ldr      w8, [x19]
0x129fe0  cbnz     w8, #0x100318
0x129fe4  ldr      x1, [x20]
0x129fe8  mov      x0, x19
0x129fec  bl       #0x147734   ; -> None
0x129ff0  ldr      w8, [x19]
0x129ff4  cbnz     w8, #0x100318
0x129ff8  mov      w21, w0
0x129ffc  ldr      x1, [x20]
0x12a000  mov      x0, x19
0x12a004  bl       #0x147734   ; -> None
0x12a008  ldr      w8, [x19]
0x12a00c  cbnz     w8, #0x100318
0x12a010  ldr      x1, [x20]
0x12a014  add      w2, w0, w21
0x12a018  mov      x0, x19
0x12a01c  bl       #0x147630   ; -> None
0x12a020  ldr      w8, [x19]
0x12a024  cbnz     w8, #0x100318
0x12a028  ldr      x1, [x20]
0x12a02c  mov      x0, x19
0x12a030  bl       #0x147734   ; -> None
0x12a034  ldr      w8, [x19]
0x12a038  cbnz     w8, #0x100318
0x12a03c  mov      w21, w0
0x12a040  ldr      x1, [x20]
0x12a044  mov      x0, x19
0x12a048  bl       #0x147734   ; -> None
0x12a04c  ldr      w8, [x19]
0x12a050  cbnz     w8, #0x100318
0x12a054  ldr      x1, [x20]
0x12a058  add      w2, w0, w21
0x12a05c  mov      x0, x19
0x12a060  bl       #0x147630   ; -> None
0x12a064  ldr      w8, [x19]
0x12a068  cbnz     w8, #0x100318
0x12a06c  ldr      x1, [x20]
0x12a070  mov      x0, x19
0x12a074  mov      w2, #0x11
0x12a078  bl       #0x147630   ; -> None
0x12a07c  ldr      w8, [x19]
0x12a080  cbnz     w8, #0x100318
0x12a084  ldr      x1, [x20]
0x12a088  mov      x0, x19
0x12a08c  bl       #0x147734   ; -> None
0x12a090  ldr      w8, [x19]
0x12a094  cbnz     w8, #0x100318
0x12a098  mov      w1, w0
0x12a09c  ldp      x21, x0, [x20]
0x12a0a0  bl       #0x147304   ; -> None
0x12a0a4  mov      w2, w0
0x12a0a8  mov      x0, x19
0x12a0ac  mov      x1, x21
0x12a0b0  bl       #0x147630   ; -> None
0x12a0b4  ldr      w8, [x19]
0x12a0b8  cbnz     w8, #0x100318
0x12a0bc  ldr      x1, [x20]
0x12a0c0  mov      x0, x19
0x12a0c4  bl       #0x147734   ; -> None
0x12a0c8  ldr      w8, [x19]
0x12a0cc  cbnz     w8, #0x100318
0x12a0d0  mov      w21, w0
0x12a0d4  ldr      x1, [x20]
0x12a0d8  mov      x0, x19
0x12a0dc  bl       #0x147734   ; -> None
0x12a0e0  ldr      w8, [x19]
0x12a0e4  cbnz     w8, #0x100318
0x12a0e8  mov      w3, w0
0x12a0ec  ldr      x1, [x26]
0x12a0f0  mov      x0, x19
0x12a0f4  mov      w2, w21
0x12a0f8  bl       #0x146ed8   ; -> None
0x12a0fc  ldr      w8, [x19]
0x12a100  cbnz     w8, #0x100318
0x12a104  ldr      x1, [x20]
0x12a108  mov      x0, x19
0x12a10c  mov      w2, #4
0x12a110  bl       #0x147630   ; -> None
0x12a114  ldr      w8, [x19]
0x12a118  cbnz     w8, #0x100318
0x12a11c  ldr      x1, [x20]
0x12a120  mov      x0, x19
0x12a124  mov      w2, #0x11
0x12a128  bl       #0x147630   ; -> None
0x12a12c  ldr      w8, [x19]
0x12a130  cbnz     w8, #0x100318
0x12a134  ldr      x1, [x20]
0x12a138  mov      x0, x19
0x12a13c  bl       #0x147734   ; -> None
0x12a140  ldr      w8, [x19]
0x12a144  cbnz     w8, #0x100318
0x12a148  mov      w1, w0
0x12a14c  ldp      x21, x0, [x20]
0x12a150  bl       #0x147304   ; -> None
0x12a154  mov      w2, w0
0x12a158  mov      x0, x19
0x12a15c  mov      x1, x21
0x12a160  bl       #0x147630   ; -> None
0x12a164  ldr      w8, [x19]
0x12a168  cbnz     w8, #0x100318
0x12a16c  ldr      x1, [x20]
0x12a170  mov      x0, x19
0x12a174  bl       #0x147734   ; -> None
0x12a178  ldr      w8, [x19]
0x12a17c  cbnz     w8, #0x100318
0x12a180  mov      w1, w0
0x12a184  ldp      x21, x0, [x20]
0x12a188  bl       #0x147304   ; -> None
0x12a18c  mov      w2, w0
0x12a190  mov      x0, x19
0x12a194  mov      x1, x21
0x12a198  bl       #0x147630   ; -> None
0x12a19c  ldr      w8, [x19]
0x12a1a0  cbnz     w8, #0x100318
0x12a1a4  ldr      x1, [x20]
0x12a1a8  mov      x0, x19
0x12a1ac  bl       #0x147734   ; -> None
0x12a1b0  ldr      w8, [x19]
0x12a1b4  cbnz     w8, #0x100318
0x12a1b8  mov      w21, w0
0x12a1bc  ldr      x1, [x20]
0x12a1c0  mov      x0, x19
0x12a1c4  bl       #0x147734   ; -> None
0x12a1c8  ldr      w8, [x19]
0x12a1cc  cbnz     w8, #0x100318
0x12a1d0  udiv     w2, w21, w0
0x12a1d4  ldr      x1, [x20]
0x12a1d8  mov      x0, x19
0x12a1dc  bl       #0x147630   ; -> None
0x12a1e0  ldr      w8, [x19]
0x12a1e4  cbnz     w8, #0x100318
0x12a1e8  ldr      x8, [sp, #0x18]
0x12a1ec  mov      x0, x19
0x12a1f0  mov      w2, #0x27f
0x12a1f4  b        #0x12a8c0
0x12a1f8  ldp      x24, x25, [sp, #8]
0x12a1fc  b.ne     #0x12a8b4
0x12a200  ldr      x1, [x20]
0x12a204  mov      x0, x19
0x12a208  mov      w2, #0x13
0x12a20c  bl       #0x147630   ; -> None
0x12a210  ldr      w8, [x19]
0x12a214  cbnz     w8, #0x100318
0x12a218  ldr      x1, [x20]
0x12a21c  mov      x0, x19
0x12a220  bl       #0x147734   ; -> None
0x12a224  ldr      w8, [x19]
0x12a228  cbnz     w8, #0x100318
0x12a22c  mov      w21, w0
0x12a230  ldr      x1, [x20]
0x12a234  mov      x0, x19
0x12a238  bl       #0x147734   ; -> None
0x12a23c  ldr      w8, [x19]
0x12a240  cbnz     w8, #0x100318
0x12a244  mov      w3, w0
0x12a248  ldr      x1, [x26]
0x12a24c  mov      x0, x19
0x12a250  mov      w2, w21
0x12a254  bl       #0x146ed8   ; -> None
0x12a258  ldr      w8, [x19]
0x12a25c  cbnz     w8, #0x100318
0x12a260  ldr      x1, [x20]
0x12a264  mov      x0, x19
0x12a268  mov      w2, #0x13
0x12a26c  bl       #0x147630   ; -> None
0x12a270  ldr      w8, [x19]
0x12a274  cbnz     w8, #0x100318
0x12a278  ldr      x1, [x20]
0x12a27c  mov      x0, x19
0x12a280  bl       #0x147734   ; -> None
0x12a284  ldr      w8, [x19]
0x12a288  cbnz     w8, #0x100318
0x12a28c  mov      w1, w0
0x12a290  ldp      x21, x0, [x20]
0x12a294  bl       #0x147304   ; -> None
0x12a298  mov      w2, w0
0x12a29c  mov      x0, x19
0x12a2a0  mov      x1, x21
0x12a2a4  bl       #0x147630   ; -> None
0x12a2a8  ldr      w8, [x19]
0x12a2ac  cbnz     w8, #0x100318
0x12a2b0  ldr      x1, [x20]
0x12a2b4  mov      x0, x19
0x12a2b8  mov      w2, #4
0x12a2bc  bl       #0x147630   ; -> None
0x12a2c0  ldr      w8, [x19]
0x12a2c4  cbnz     w8, #0x100318
0x12a2c8  ldr      x1, [x20]
0x12a2cc  mov      x0, x19
0x12a2d0  bl       #0x147734   ; -> None
0x12a2d4  ldr      w8, [x19]
0x12a2d8  cbnz     w8, #0x100318
0x12a2dc  ldr      x8, [sp]
0x12a2e0  mov      w2, w0
0x12a2e4  mov      x0, x19
0x12a2e8  ldr      x1, [x8]
0x12a2ec  bl       #0x146558   ; -> None
0x12a2f0  ldr      w8, [x19]
0x12a2f4  cbnz     w8, #0x100318
0x12a2f8  ldr      x21, [x20]
0x12a2fc  bl       #0x148d10   ; -> rand
0x12a300  mov      w2, w0
0x12a304  mov      x0, x19
0x12a308  mov      x1, x21
0x12a30c  bl       #0x147630   ; -> None
0x12a310  ldr      w8, [x19]
0x12a314  cbnz     w8, #0x100318
0x12a318  ldr      x21, [x20]
0x12a31c  bl       #0x148d10   ; -> rand
0x12a320  mov      w2, w0
0x12a324  mov      x0, x19
0x12a328  mov      x1, x21
0x12a32c  bl       #0x147630   ; -> None
0x12a330  ldr      w8, [x19]
0x12a334  cbnz     w8, #0x100318
0x12a338  ldr      x1, [x20]
0x12a33c  mov      x0, x19
0x12a340  bl       #0x147734   ; -> None
0x12a344  ldr      w8, [x19]
0x12a348  cbnz     w8, #0x100318
0x12a34c  mov      w21, w0
0x12a350  ldr      x1, [x20]
0x12a354  mov      x0, x19
0x12a358  bl       #0x147734   ; -> None
0x12a35c  ldr      w8, [x19]
0x12a360  cbnz     w8, #0x100318
0x12a364  ldr      x1, [x20]
0x12a368  eor      w2, w0, w21
0x12a36c  mov      x0, x19
0x12a370  bl       #0x147630   ; -> None
0x12a374  ldr      w8, [x19]
0x12a378  cbnz     w8, #0x100318
0x12a37c  ldr      x1, [x20]
0x12a380  mov      x0, x19
0x12a384  mov      w2, #1
0x12a388  bl       #0x14784c   ; -> None
0x12a38c  ldr      w8, [x19]
0x12a390  cbnz     w8, #0x100318
0x12a394  ldr      x1, [x20]
0x12a398  mov      x0, x19
0x12a39c  bl       #0x147734   ; -> None
0x12a3a0  ldr      w8, [x19]
0x12a3a4  cbnz     w8, #0x100318
0x12a3a8  mov      w21, w0
0x12a3ac  ldr      x1, [x20]
0x12a3b0  mov      x0, x19
0x12a3b4  bl       #0x147734   ; -> None
0x12a3b8  ldr      w8, [x19]
0x12a3bc  cbnz     w8, #0x100318
0x12a3c0  mov      w3, w0
0x12a3c4  ldr      x1, [x26]
0x12a3c8  mov      x0, x19
0x12a3cc  mov      w2, w21
0x12a3d0  bl       #0x146ed8   ; -> None
0x12a3d4  ldr      w8, [x19]
0x12a3d8  cbnz     w8, #0x100318
0x12a3dc  ldr      x1, [x20]
0x12a3e0  mov      x0, x19
0x12a3e4  bl       #0x147734   ; -> None
0x12a3e8  ldr      w8, [x19]
0x12a3ec  cbnz     w8, #0x100318
0x12a3f0  ldr      x1, [x20]
0x12a3f4  add      w2, w0, #1
0x12a3f8  mov      x0, x19
0x12a3fc  bl       #0x147630   ; -> None
0x12a400  ldr      w8, [x19]
0x12a404  cbnz     w8, #0x100318
0x12a408  ldr      x8, [sp]
0x12a40c  ldr      x0, [x8]
0x12a410  bl       #0x146650   ; -> None
0x12a414  cbnz     w0, #0x12a2f8
0x12a418  ldr      x1, [x20]
0x12a41c  mov      x0, x19
0x12a420  bl       #0x147734   ; -> None
0x12a424  ldr      w8, [x19]
0x12a428  cbnz     w8, #0x100318
0x12a42c  ldr      x1, [x20]
0x12a430  mov      x0, x19
0x12a434  mov      w2, #0x14
0x12a438  bl       #0x147630   ; -> None
0x12a43c  ldr      w8, [x19]
0x12a440  cbnz     w8, #0x100318
0x12a444  ldr      x1, [x20]
0x12a448  mov      x0, x19
0x12a44c  bl       #0x147734   ; -> None
0x12a450  ldr      w8, [x19]
0x12a454  cbnz     w8, #0x100318
0x12a458  mov      w1, w0
0x12a45c  ldp      x21, x0, [x20]
0x12a460  bl       #0x147304   ; -> None
0x12a464  mov      w2, w0
0x12a468  mov      x0, x19
0x12a46c  mov      x1, x21
0x12a470  bl       #0x147630   ; -> None
0x12a474  ldr      w8, [x19]
0x12a478  cbnz     w8, #0x100318
0x12a47c  ldr      x1, [x20]
0x12a480  mov      x0, x19
0x12a484  bl       #0x147734   ; -> None
0x12a488  ldr      w8, [x19]
0x12a48c  cbnz     w8, #0x100318
0x12a490  mov      w1, w0
0x12a494  ldp      x21, x0, [x20]
0x12a498  bl       #0x147304   ; -> None
0x12a49c  mov      w2, w0
0x12a4a0  mov      x0, x19
0x12a4a4  mov      x1, x21
0x12a4a8  bl       #0x147630   ; -> None
0x12a4ac  ldr      w8, [x19]
0x12a4b0  cbnz     w8, #0x100318
0x12a4b4  ldr      x1, [x20]
0x12a4b8  mov      x0, x19
0x12a4bc  mov      w2, #4
0x12a4c0  bl       #0x147630   ; -> None
0x12a4c4  ldr      w8, [x19]
0x12a4c8  cbnz     w8, #0x100318
0x12a4cc  ldr      x1, [x20]
0x12a4d0  mov      x0, x19
0x12a4d4  bl       #0x147734   ; -> None
0x12a4d8  ldr      w8, [x19]
0x12a4dc  cbnz     w8, #0x100318
0x12a4e0  mov      w21, w0
0x12a4e4  ldr      x1, [x20]
0x12a4e8  mov      x0, x19
0x12a4ec  bl       #0x147734   ; -> None
0x12a4f0  ldr      w8, [x19]
0x12a4f4  cbnz     w8, #0x100318
0x12a4f8  ldr      x1, [x20]
0x12a4fc  add      w2, w0, w21
0x12a500  mov      x0, x19
0x12a504  bl       #0x147630   ; -> None
0x12a508  ldr      w8, [x19]
0x12a50c  cbnz     w8, #0x100318
0x12a510  ldr      x1, [x20]
0x12a514  mov      x0, x19
0x12a518  mov      w2, #8
0x12a51c  bl       #0x147630   ; -> None
0x12a520  ldr      w8, [x19]
0x12a524  cbnz     w8, #0x100318
0x12a528  ldr      x1, [x20]
0x12a52c  mov      x0, x19
0x12a530  bl       #0x147734   ; -> None
0x12a534  ldr      w8, [x19]
0x12a538  cbnz     w8, #0x100318
0x12a53c  mov      w21, w0
0x12a540  ldr      x1, [x20]
0x12a544  mov      x0, x19
0x12a548  bl       #0x147734   ; -> None
0x12a54c  ldr      w8, [x19]
0x12a550  cbnz     w8, #0x100318
0x12a554  ldr      x1, [x20]
0x12a558  add      w2, w0, w21
0x12a55c  mov      x0, x19
0x12a560  bl       #0x147630   ; -> None
0x12a564  ldr      w8, [x19]
0x12a568  cbnz     w8, #0x100318
0x12a56c  ldr      x8, [sp, #0x18]
0x12a570  mov      x0, x19
0x12a574  mov      w2, #0x319
0x12a578  b        #0x12a8c0
0x12a57c  ldp      x24, x25, [sp, #8]
0x12a580  b.ne     #0x12a8b4
0x12a584  ldr      x1, [x20]
0x12a588  mov      x0, x19
0x12a58c  mov      w2, #4
0x12a590  bl       #0x147630   ; -> None
0x12a594  ldr      w8, [x19]
0x12a598  cbnz     w8, #0x100318
0x12a59c  ldr      x1, [x20]
0x12a5a0  mov      x0, x19
0x12a5a4  bl       #0x147734   ; -> None
0x12a5a8  ldr      w8, [x19]
0x12a5ac  cbnz     w8, #0x100318
0x12a5b0  mov      w21, w0
0x12a5b4  ldr      x1, [x20]
0x12a5b8  mov      x0, x19
0x12a5bc  bl       #0x147734   ; -> None
0x12a5c0  ldr      w8, [x19]
0x12a5c4  cbnz     w8, #0x100318
0x12a5c8  mov      w3, w0
0x12a5cc  ldr      x1, [x26]
0x12a5d0  mov      x0, x19
0x12a5d4  mov      w2, w21
0x12a5d8  bl       #0x146ed8   ; -> None
0x12a5dc  ldr      w8, [x19]
0x12a5e0  cbnz     w8, #0x100318
0x12a5e4  ldr      x1, [x20]
0x12a5e8  mov      x0, x19
0x12a5ec  mov      w2, #5
0x12a5f0  bl       #0x147630   ; -> None
0x12a5f4  ldr      w8, [x19]
0x12a5f8  cbnz     w8, #0x100318
0x12a5fc  ldr      x8, [sp, #0x18]
0x12a600  mov      x0, x19
0x12a604  mov      w2, #0x7d
0x12a608  b        #0x12a8c0
0x12a60c  ldp      x24, x25, [sp, #8]
0x12a610  b.ne     #0x12a8b4
0x12a614  ldr      x1, [x20]
0x12a618  mov      x0, x19
0x12a61c  mov      w2, #0xe
0x12a620  bl       #0x147630   ; -> None
0x12a624  ldr      w8, [x19]
0x12a628  cbnz     w8, #0x100318
0x12a62c  ldr      x1, [x20]
0x12a630  mov      x0, x19
0x12a634  bl       #0x147734   ; -> None
0x12a638  ldr      w8, [x19]
0x12a63c  cbnz     w8, #0x100318
0x12a640  mov      w21, w0
0x12a644  ldr      x1, [x20]
0x12a648  mov      x0, x19
0x12a64c  bl       #0x147734   ; -> None
0x12a650  ldr      w8, [x19]
0x12a654  cbnz     w8, #0x100318
0x12a658  mov      w3, w0
0x12a65c  ldr      x1, [x26]
0x12a660  mov      x0, x19
0x12a664  mov      w2, w21
0x12a668  bl       #0x146ed8   ; -> None
0x12a66c  ldr      w8, [x19]
0x12a670  cbnz     w8, #0x100318
0x12a674  ldr      x1, [x20]
0x12a678  mov      x0, x19
0x12a67c  mov      w2, #8
0x12a680  bl       #0x147630   ; -> None
0x12a684  ldr      w8, [x19]
0x12a688  cbnz     w8, #0x100318
0x12a68c  ldr      x1, [x20]
0x12a690  mov      x0, x19
0x12a694  mov      w2, #0xe
0x12a698  bl       #0x147630   ; -> None
0x12a69c  ldr      w8, [x19]
0x12a6a0  cbnz     w8, #0x100318
0x12a6a4  ldr      x1, [x20]
0x12a6a8  mov      x0, x19
0x12a6ac  bl       #0x147734   ; -> None
0x12a6b0  ldr      w8, [x19]
0x12a6b4  cbnz     w8, #0x100318
0x12a6b8  mov      w1, w0
0x12a6bc  ldp      x21, x0, [x20]
0x12a6c0  bl       #0x147304   ; -> None
0x12a6c4  mov      w2, w0
0x12a6c8  mov      x0, x19
0x12a6cc  mov      x1, x21
0x12a6d0  bl       #0x147630   ; -> None
0x12a6d4  ldr      w8, [x19]
0x12a6d8  cbnz     w8, #0x100318
0x12a6dc  ldr      x1, [x20]
0x12a6e0  mov      x0, x19
0x12a6e4  bl       #0x147734   ; -> None
0x12a6e8  ldr      w8, [x19]
0x12a6ec  cbnz     w8, #0x100318
0x12a6f0  mov      w21, w0
0x12a6f4  ldr      x1, [x20]
0x12a6f8  mov      x0, x19
0x12a6fc  bl       #0x147734   ; -> None
0x12a700  ldr      w8, [x19]
0x12a704  cbnz     w8, #0x100318
0x12a708  add      x28, x20, w0, uxtw #3
0x12a70c  ldr      x0, [x28, #0x20]!
0x12a710  bl       #0x1472e8   ; -> None
0x12a714  mov      w22, w0
0x12a718  mov      w23, wzr
0x12a71c  cmp      w22, w23
0x12a720  b.eq     #0x12a9dc
0x12a724  ldr      x0, [x28]
0x12a728  mov      w1, w23
0x12a72c  ldr      x24, [x26]
0x12a730  add      w25, w21, w23
0x12a734  bl       #0x147304   ; -> None
0x12a738  mov      w3, w0
0x12a73c  mov      x0, x19
0x12a740  mov      x1, x24
0x12a744  mov      w2, w25
0x12a748  bl       #0x146ed8   ; -> None
0x12a74c  ldp      x24, x25, [sp, #8]
0x12a750  add      w23, w23, #1
0x12a754  ldr      w8, [x19]
0x12a758  cbz      w8, #0x12a71c
0x12a75c  b        #0x100318
0x12a760  ldp      x24, x25, [sp, #8]
0x12a764  b.ne     #0x12a8b4
0x12a768  ldr      x1, [x20]
0x12a76c  mov      x0, x19
0x12a770  mov      w2, #0xb
0x12a774  bl       #0x147630   ; -> None
0x12a778  ldr      w8, [x19]
0x12a77c  cbnz     w8, #0x100318
0x12a780  ldr      x1, [x20]
0x12a784  mov      x0, x19
0x12a788  bl       #0x147734   ; -> None
0x12a78c  ldr      w8, [x19]
0x12a790  cbnz     w8, #0x100318
0x12a794  mov      w21, w0
0x12a798  ldr      x1, [x20]
0x12a79c  mov      x0, x19
0x12a7a0  bl       #0x147734   ; -> None
0x12a7a4  ldr      w8, [x19]
0x12a7a8  cbnz     w8, #0x100318
0x12a7ac  mov      w3, w0
