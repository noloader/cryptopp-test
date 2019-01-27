# aes_aix.s version 20050205
# D. J. Bernstein
# Public domain.

# translated by qhasm-ppc version 20050205
.toc
.addr.aes_aix_constants:
.tc aes_aix_constants[tc],aes_aix_constants[rw]
.extern aes_aix_constants[rw]

# input line 1: register int32 out

# input line 2: register int32 k

# input line 3: register int32 n

# input line 4: register int32 table0

# input line 5: register int32 table1

# input line 6: register int32 table2

# input line 7: register int32 table3

# input line 8: register int32 e

# input line 9: register int32 x0

# input line 10: register int32 x1

# input line 11: register int32 x2

# input line 12: register int32 x3

# input line 13: register int32 z0

# input line 14: register int32 z1

# input line 15: register int32 z2

# input line 16: register int32 z3

# input line 17: register int32 y0

# input line 18: register int32 p03

# input line 19: register int32 y1

# input line 20: register int32 p13

# input line 21: register int32 p32

# input line 22: register int32 y2

# input line 23: register int32 p23

# input line 24: register int32 p31

# input line 25: register int32 y3

# input line 26: register int32 p33

# input line 27: register int32 p30

# input line 28: register int32 loop4

# input line 29: register int32 q3

# input line 30: register int32 q2

# input line 31: register int32 q1

# input line 32: register int32 q0

# input line 33: register int32 f

# input line 34: register int32 p00

# input line 35: register int32 p01

# input line 36: register int32 p02

# input line 37: register int32 p10

# input line 38: register int32 p11

# input line 39: register int32 p12

# input line 40: register int32 p20

# input line 41: register int32 p21

# input line 42: register int32 p22

# input line 43: register int32 v0

# input line 44: register int32 v1

# input line 45: register int32 v2

# input line 46: register int32 v3

# input line 47: register int32 r03

# input line 48: register int32 r13

# input line 49: register int32 r23

# input line 50: register int32 r33

# input line 51: register int32 r02

# input line 52: register int32 r12

# input line 53: register int32 r22

# input line 54: register int32 r32

# input line 55: register int32 r01

# input line 56: register int32 r11

# input line 57: register int32 r21

# input line 58: register int32 r31

# input line 59: register int32 r00

# input line 60: register int32 r10

# input line 61: register int32 r20

# input line 62: register int32 r30

# input line 63: 

# input line 64: extern aes_aix_constants

# input line 65: 

# input line 66: enter aes_aix
.csect aes_aix[DS]
.globl aes_aix
aes_aix:
.long .aes_aix
.long TOC[tc0]
.long 0
.csect .text[PR]
.globl .aes_aix
.aes_aix:
stwu 1,-192(1)

# input line 67: input out

# input line 68: input k

# input line 69: input n

# input line 70: 

# input line 71:   store callerint 31
# %caller_r31@stack = %caller_r31
# mem32#14 = int32#29
# 180(1) = 31
stw 31,180(1)
# live mem32 values: 1
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 72:   store callerint 30
# %caller_r30@stack = %caller_r30
# mem32#13 = int32#28
# 176(1) = 30
stw 30,176(1)
# live mem32 values: 2
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 73:   store callerint 29
# %caller_r29@stack = %caller_r29
# mem32#12 = int32#27
# 172(1) = 29
stw 29,172(1)
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 19
# live double values: 18
# live flags values: 0

# input line 74:   store callerint 28
# %caller_r28@stack = %caller_r28
# mem32#11 = int32#26
# 168(1) = 28
stw 28,168(1)
# live mem32 values: 4
# live flag values: 0
# live mem64 values: 0
# live int32 values: 18
# live double values: 18
# live flags values: 0

# input line 75:   store callerint 27
# %caller_r27@stack = %caller_r27
# mem32#10 = int32#25
# 164(1) = 27
stw 27,164(1)
# live mem32 values: 5
# live flag values: 0
# live mem64 values: 0
# live int32 values: 17
# live double values: 18
# live flags values: 0

# input line 76:   store callerint 26
# %caller_r26@stack = %caller_r26
# mem32#9 = int32#24
# 160(1) = 26
stw 26,160(1)
# live mem32 values: 6
# live flag values: 0
# live mem64 values: 0
# live int32 values: 16
# live double values: 18
# live flags values: 0

# input line 77:   store callerint 25
# %caller_r25@stack = %caller_r25
# mem32#8 = int32#23
# 156(1) = 25
stw 25,156(1)
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 15
# live double values: 18
# live flags values: 0

# input line 78:   store callerint 24
# %caller_r24@stack = %caller_r24
# mem32#7 = int32#22
# 152(1) = 24
stw 24,152(1)
# live mem32 values: 8
# live flag values: 0
# live mem64 values: 0
# live int32 values: 14
# live double values: 18
# live flags values: 0

# input line 79:   store callerint 23
# %caller_r23@stack = %caller_r23
# mem32#6 = int32#21
# 148(1) = 23
stw 23,148(1)
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 13
# live double values: 18
# live flags values: 0

# input line 80:   store callerint 22
# %caller_r22@stack = %caller_r22
# mem32#5 = int32#20
# 144(1) = 22
stw 22,144(1)
# live mem32 values: 10
# live flag values: 0
# live mem64 values: 0
# live int32 values: 12
# live double values: 18
# live flags values: 0

# input line 81:   store callerint 21
# %caller_r21@stack = %caller_r21
# mem32#4 = int32#19
# 140(1) = 21
stw 21,140(1)
# live mem32 values: 11
# live flag values: 0
# live mem64 values: 0
# live int32 values: 11
# live double values: 18
# live flags values: 0

# input line 82:   store callerint 20
# %caller_r20@stack = %caller_r20
# mem32#3 = int32#18
# 136(1) = 20
stw 20,136(1)
# live mem32 values: 12
# live flag values: 0
# live mem64 values: 0
# live int32 values: 10
# live double values: 18
# live flags values: 0

# input line 83:   store callerint 19
# %caller_r19@stack = %caller_r19
# mem32#2 = int32#17
# 132(1) = 19
stw 19,132(1)
# live mem32 values: 13
# live flag values: 0
# live mem64 values: 0
# live int32 values: 9
# live double values: 18
# live flags values: 0

# input line 84:   store callerint 18
# %caller_r18@stack = %caller_r18
# mem32#1 = int32#16
# 128(1) = 18
stw 18,128(1)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 8
# live double values: 18
# live flags values: 0

# input line 85: 

# input line 86:   x3 = *(uint32 *) (k + 12)
# x3 = *(int16 *) (k + 12)
# int32#19 = *(int16 *) (int32#2 + 12)
# 21 = *(int16 *) (4 + 12)
lwz 21,12(4)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 9
# live double values: 18
# live flags values: 0

# input line 87:   table0 = &aes_aix_constants
# table0 = aes_aix_constants
# int32#4 = aes_aix_constants
# 6 = aes_aix_constants
lwz 6,.addr.aes_aix_constants(2)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 10
# live double values: 18
# live flags values: 0

# input line 88: 

# input line 89:   x0 = *(uint32 *) (k + 0)
# x0 = *(int16 *) (k + 0)
# int32#8 = *(int16 *) (int32#2 + 0)
# 10 = *(int16 *) (4 + 0)
lwz 10,0(4)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 11
# live double values: 18
# live flags values: 0

# input line 90:   table1 = table0 + 3
# table1 = table0 + 3
# int32#5 = int32#4 + 3
# 7 = 6 + 3
addi 7,6,3
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 12
# live double values: 18
# live flags values: 0

# input line 91: 

# input line 92:   x1 = *(uint32 *) (k + 4)
# x1 = *(int16 *) (k + 4)
# int32#9 = *(int16 *) (int32#2 + 4)
# 11 = *(int16 *) (4 + 4)
lwz 11,4(4)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 13
# live double values: 18
# live flags values: 0

# input line 93:   table2 = table0 + 2
# table2 = table0 + 2
# int32#6 = int32#4 + 2
# 8 = 6 + 2
addi 8,6,2
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 14
# live double values: 18
# live flags values: 0

# input line 94: 

# input line 95:   x2 = *(uint32 *) (k + 8)
# x2 = *(int16 *) (k + 8)
# int32#10 = *(int16 *) (int32#2 + 8)
# 12 = *(int16 *) (4 + 8)
lwz 12,8(4)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 14
# live double values: 18
# live flags values: 0

# input line 96:   table3 = table0 + 1
# table3 = table0 + 1
# int32#2 = int32#4 + 1
# 4 = 6 + 1
addi 4,6,1
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 15
# live double values: 18
# live flags values: 0

# input line 97: 

# input line 98:   q0 = 0x7f8 & (x3 <<< 19)
# q0 = 0x7f8 & (x3 <<< 19)
# int32#7 = 0x7f8 & (int32#19 <<< 19)
# 9 = 0x7f8 & (21 <<< 19)
rlwinm 9,21,19,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 16
# live double values: 18
# live flags values: 0

# input line 99:   loop4 = "-36"
# loop4 = -36
# int32#24 = -36
# 26 = -36
li 26,-36
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 17
# live double values: 18
# live flags values: 0

# input line 100: 

# input line 101:   q0 = *(uint32 *) (table2 + q0)
# q0#2 = *(int16 *) (table2 + q0)
# int32#16 = *(int16 *) (int32#6 + int32#7)
# 18 = *(int16 *) (8 + 9)
lwzx 18,8,9
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 17
# live double values: 18
# live flags values: 0

# input line 102:   q1 = 0x7f8 & (x3 <<< 27)
# q1 = 0x7f8 & (x3 <<< 27)
# int32#7 = 0x7f8 & (int32#19 <<< 27)
# 9 = 0x7f8 & (21 <<< 27)
rlwinm 9,21,27,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 18
# live double values: 18
# live flags values: 0

# input line 103: 

# input line 104:   q1 = *(uint32 *) (table3 + q1)
# q1#2 = *(int16 *) (table3 + q1)
# int32#17 = *(int16 *) (int32#2 + int32#7)
# 19 = *(int16 *) (4 + 9)
lwzx 19,4,9
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 18
# live double values: 18
# live flags values: 0

# input line 105:   q2 = 0x7f8 & (x3 <<< 3)
# q2 = 0x7f8 & (x3 <<< 3)
# int32#7 = 0x7f8 & (int32#19 <<< 3)
# 9 = 0x7f8 & (21 <<< 3)
rlwinm 9,21,3,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 19
# live double values: 18
# live flags values: 0

# input line 106: 

# input line 107:   q2 = *(uint32 *) (table0 + q2)
# q2#2 = *(int16 *) (table0 + q2)
# int32#18 = *(int16 *) (int32#4 + int32#7)
# 20 = *(int16 *) (6 + 9)
lwzx 20,6,9
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 19
# live double values: 18
# live flags values: 0

# input line 108:   q3 = 0x7f8 & (x3 <<< 11)
# q3 = 0x7f8 & (x3 <<< 11)
# int32#7 = 0x7f8 & (int32#19 <<< 11)
# 9 = 0x7f8 & (21 <<< 11)
rlwinm 9,21,11,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 109: 

# input line 110:   q3 = *(uint32 *) (table1 + q3)
# q3#2 = *(int16 *) (table1 + q3)
# int32#20 = *(int16 *) (int32#5 + int32#7)
# 22 = *(int16 *) (7 + 9)
lwzx 22,7,9
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 111:   e = 0xff000000 & (q0 <<< 0)
# e = 0xff000000 & (q0#2 <<< 0)
# int32#7 = 0xff000000 & (int32#16 <<< 0)
# 9 = 0xff000000 & (18 <<< 0)
rlwinm 9,18,0,0xff000000
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 112: 

# input line 113:   y0 = *(uint32 *) (n + 0)
# y0 = *(int16 *) (n + 0)
# int32#16 = *(int16 *) (int32#3 + 0)
# 18 = *(int16 *) (5 + 0)
lwz 18,0(5)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 114:   e bits 0xff0000 = q1 <<< 0
# e bits 0xff0000 = q1#2 <<< 0
# int32#7 bits 0xff0000 = int32#17 <<< 0
# 9 bits 0xff0000 = 19 <<< 0
rlwimi 9,19,0,0xff0000
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 115: 

# input line 116:   y1 = *(uint32 *) (n + 4)
# y1 = *(int16 *) (n + 4)
# int32#17 = *(int16 *) (int32#3 + 4)
# 19 = *(int16 *) (5 + 4)
lwz 19,4(5)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 117:   e bits 0xff00 = q2 <<< 0
# e bits 0xff00 = q2#2 <<< 0
# int32#7 bits 0xff00 = int32#18 <<< 0
# 9 bits 0xff00 = 20 <<< 0
rlwimi 9,20,0,0xff00
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 118: 

# input line 119:   y2 = *(uint32 *) (n + 8)
# y2 = *(int16 *) (n + 8)
# int32#18 = *(int16 *) (int32#3 + 8)
# 20 = *(int16 *) (5 + 8)
lwz 20,8(5)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 120:   e bits 0xff = q3 <<< 0
# e bits 0xff = q3#2 <<< 0
# int32#7 bits 0xff = int32#20 <<< 0
# 9 bits 0xff = 22 <<< 0
rlwimi 9,22,0,0xff
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 121: 

# input line 122:   y3 = *(uint32 *) (n + 12)
# y3 = *(int16 *) (n + 12)
# int32#20 = *(int16 *) (int32#3 + 12)
# 22 = *(int16 *) (5 + 12)
lwz 22,12(5)
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 123:   y0 ^= x0
# y0#2 = y0 ^ x0
# int32#21 = int32#16 ^ int32#8
# 23 = 18 ^ 10
xor 23,18,10
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 124: 

# input line 125:   e ^= 65536 * 0x0100
# e#2 = e ^ 65536 * 0x0100
# int32#3 = int32#7 ^ 65536 * 0x0100
# 5 = 9 ^ 65536 * 0x0100
xoris 5,9,0x0100
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 126:   y1 ^= x1
# y1#2 = y1 ^ x1
# int32#22 = int32#17 ^ int32#9
# 24 = 19 ^ 11
xor 24,19,11
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 127: 

# input line 128:   y2 ^= x2
# y2#2 = y2 ^ x2
# int32#23 = int32#18 ^ int32#10
# 25 = 20 ^ 12
xor 25,20,12
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 129:   y3 ^= x3
# y3#2 = y3 ^ x3
# int32#27 = int32#20 ^ int32#19
# 29 = 22 ^ 21
xor 29,22,21
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 130:   

# input line 131: mainloop
.label.mainloop:

# input line 132:   p00 = 0x7f8 & (y0 <<< 11)
# p00 = 0x7f8 & (y0#2 <<< 11)
# int32#7 = 0x7f8 & (int32#21 <<< 11)
# 9 = 0x7f8 & (23 <<< 11)
rlwinm 9,23,11,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 133:   x0 ^= e
# x0 = x0 ^ e#2
# int32#8 = int32#8 ^ int32#3
# 10 = 10 ^ 5
xor 10,10,5
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 134: 

# input line 135:   p00 = *(uint32 *) (table0 + p00)
# p00#2 = *(int16 *) (table0 + p00)
# int32#16 = *(int16 *) (int32#4 + int32#7)
# 18 = *(int16 *) (6 + 9)
lwzx 18,6,9
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 136:   p01 = 0x7f8 & (y0 <<< 19)
# p01 = 0x7f8 & (y0#2 <<< 19)
# int32#3 = 0x7f8 & (int32#21 <<< 19)
# 5 = 0x7f8 & (23 <<< 19)
rlwinm 5,23,19,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 137:   x1 ^= x0
# x1 = x1 ^ x0
# int32#9 = int32#9 ^ int32#8
# 11 = 11 ^ 10
xor 11,11,10
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 138: 

# input line 139:   p01 = *(uint32 *) (table1 + p01)
# p01#2 = *(int16 *) (table1 + p01)
# int32#17 = *(int16 *) (int32#5 + int32#3)
# 19 = *(int16 *) (7 + 5)
lwzx 19,7,5
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 140:   p02 = 0x7f8 & (y0 <<< 27)
# p02 = 0x7f8 & (y0#2 <<< 27)
# int32#3 = 0x7f8 & (int32#21 <<< 27)
# 5 = 0x7f8 & (23 <<< 27)
rlwinm 5,23,27,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 141:   x2 ^= x1
# x2 = x2 ^ x1
# int32#10 = int32#10 ^ int32#9
# 12 = 12 ^ 11
xor 12,12,11
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 142: 

# input line 143:   p02 = *(uint32 *) (table2 + p02)
# p02#2 = *(int16 *) (table2 + p02)
# int32#18 = *(int16 *) (int32#6 + int32#3)
# 20 = *(int16 *) (8 + 5)
lwzx 20,8,5
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 144:   p03 = 0x7f8 & (y0 <<< 3)
# p03 = 0x7f8 & (y0#2 <<< 3)
# int32#3 = 0x7f8 & (int32#21 <<< 3)
# 5 = 0x7f8 & (23 <<< 3)
rlwinm 5,23,3,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 145:   x3 ^= x2
# x3 = x3 ^ x2
# int32#19 = int32#19 ^ int32#10
# 21 = 21 ^ 12
xor 21,21,12
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 146: 

# input line 147:   p03 = *(uint32 *) (table3 + p03)
# p03#2 = *(int16 *) (table3 + p03)
# int32#7 = *(int16 *) (int32#2 + int32#3)
# 9 = *(int16 *) (4 + 5)
lwzx 9,4,5
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 148:   p10 = 0x7f8 & (y1 <<< 11)
# p10 = 0x7f8 & (y1#2 <<< 11)
# int32#20 = 0x7f8 & (int32#22 <<< 11)
# 22 = 0x7f8 & (24 <<< 11)
rlwinm 22,24,11,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 149:   z0 = x0 ^ p00
# z0 = x0 ^ p00#2
# int32#3 = int32#8 ^ int32#16
# 5 = 10 ^ 18
xor 5,10,18
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 150: 

# input line 151:   p10 = *(uint32 *) (table0 + p10)
# p10#2 = *(int16 *) (table0 + p10)
# int32#21 = *(int16 *) (int32#4 + int32#20)
# 23 = *(int16 *) (6 + 22)
lwzx 23,6,22
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 152:   p11 = 0x7f8 & (y1 <<< 19)
# p11 = 0x7f8 & (y1#2 <<< 19)
# int32#16 = 0x7f8 & (int32#22 <<< 19)
# 18 = 0x7f8 & (24 <<< 19)
rlwinm 18,24,19,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 153:   z3 = x3 ^ p01
# z3 = x3 ^ p01#2
# int32#17 = int32#19 ^ int32#17
# 19 = 21 ^ 19
xor 19,21,19
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 154: 

# input line 155:   p11 = *(uint32 *) (table1 + p11)
# p11#2 = *(int16 *) (table1 + p11)
# int32#25 = *(int16 *) (int32#5 + int32#16)
# 27 = *(int16 *) (7 + 18)
lwzx 27,7,18
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 156:   p12 = 0x7f8 & (y1 <<< 27)
# p12 = 0x7f8 & (y1#2 <<< 27)
# int32#20 = 0x7f8 & (int32#22 <<< 27)
# 22 = 0x7f8 & (24 <<< 27)
rlwinm 22,24,27,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 157:   z2 = x2 ^ p02
# z2 = x2 ^ p02#2
# int32#16 = int32#10 ^ int32#18
# 18 = 12 ^ 20
xor 18,12,20
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 158: 

# input line 159:   p12 = *(uint32 *) (table2 + p12)
# p12#2 = *(int16 *) (table2 + p12)
# int32#26 = *(int16 *) (int32#6 + int32#20)
# 28 = *(int16 *) (8 + 22)
lwzx 28,8,22
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 160:   p13 = 0x7f8 & (y1 <<< 3)
# p13 = 0x7f8 & (y1#2 <<< 3)
# int32#18 = 0x7f8 & (int32#22 <<< 3)
# 20 = 0x7f8 & (24 <<< 3)
rlwinm 20,24,3,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 161:   z1 = x1 ^ p03
# z1 = x1 ^ p03#2
# int32#7 = int32#9 ^ int32#7
# 9 = 11 ^ 9
xor 9,11,9
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 162: 

# input line 163:   p13 = *(uint32 *) (table3 + p13)
# p13#2 = *(int16 *) (table3 + p13)
# int32#20 = *(int16 *) (int32#2 + int32#18)
# 22 = *(int16 *) (4 + 20)
lwzx 22,4,20
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 164:   p20 = 0x7f8 & (y2 <<< 11)
# p20 = 0x7f8 & (y2#2 <<< 11)
# int32#18 = 0x7f8 & (int32#23 <<< 11)
# 20 = 0x7f8 & (25 <<< 11)
rlwinm 20,25,11,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 165:   z1 ^= p10
# z1#2 = z1 ^ p10#2
# int32#7 = int32#7 ^ int32#21
# 9 = 9 ^ 23
xor 9,9,23
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 166: 

# input line 167:   p20 = *(uint32 *) (table0 + p20)
# p20#2 = *(int16 *) (table0 + p20)
# int32#22 = *(int16 *) (int32#4 + int32#18)
# 24 = *(int16 *) (6 + 20)
lwzx 24,6,20
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 168:   p21 = 0x7f8 & (y2 <<< 19)
# p21 = 0x7f8 & (y2#2 <<< 19)
# int32#18 = 0x7f8 & (int32#23 <<< 19)
# 20 = 0x7f8 & (25 <<< 19)
rlwinm 20,25,19,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 169:   z0 ^= p11
# z0#2 = z0 ^ p11#2
# int32#3 = int32#3 ^ int32#25
# 5 = 5 ^ 27
xor 5,5,27
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 170: 

# input line 171:   p21 = *(uint32 *) (table1 + p21)
# p21#2 = *(int16 *) (table1 + p21)
# int32#25 = *(int16 *) (int32#5 + int32#18)
# 27 = *(int16 *) (7 + 20)
lwzx 27,7,20
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 172:   p22 = 0x7f8 & (y2 <<< 27)
# p22 = 0x7f8 & (y2#2 <<< 27)
# int32#21 = 0x7f8 & (int32#23 <<< 27)
# 23 = 0x7f8 & (25 <<< 27)
rlwinm 23,25,27,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 173:   z3 ^= p12
# z3#2 = z3 ^ p12#2
# int32#18 = int32#17 ^ int32#26
# 20 = 19 ^ 28
xor 20,19,28
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 174: 

# input line 175:   p22 = *(uint32 *) (table2 + p22)
# p22#2 = *(int16 *) (table2 + p22)
# int32#26 = *(int16 *) (int32#6 + int32#21)
# 28 = *(int16 *) (8 + 23)
lwzx 28,8,23
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 176:   p23 = 0x7f8 & (y2 <<< 3)
# p23 = 0x7f8 & (y2#2 <<< 3)
# int32#17 = 0x7f8 & (int32#23 <<< 3)
# 19 = 0x7f8 & (25 <<< 3)
rlwinm 19,25,3,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 177:   z2 ^= p13
# z2#2 = z2 ^ p13#2
# int32#16 = int32#16 ^ int32#20
# 18 = 18 ^ 22
xor 18,18,22
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 178: 

# input line 179:   p23 = *(uint32 *) (table3 + p23)
# p23#2 = *(int16 *) (table3 + p23)
# int32#21 = *(int16 *) (int32#2 + int32#17)
# 23 = *(int16 *) (4 + 19)
lwzx 23,4,19
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 180:   p30 = 0x7f8 & (y3 <<< 11)
# p30 = 0x7f8 & (y3#2 <<< 11)
# int32#20 = 0x7f8 & (int32#27 <<< 11)
# 22 = 0x7f8 & (29 <<< 11)
rlwinm 22,29,11,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 181:   z2 ^= p20
# z2#3 = z2#2 ^ p20#2
# int32#17 = int32#16 ^ int32#22
# 19 = 18 ^ 24
xor 19,18,24
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 182: 

# input line 183:   p30 = *(uint32 *) (table0 + p30)
# p30#2 = *(int16 *) (table0 + p30)
# int32#23 = *(int16 *) (int32#4 + int32#20)
# 25 = *(int16 *) (6 + 22)
lwzx 25,6,22
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 184:   p31 = 0x7f8 & (y3 <<< 19)
# p31 = 0x7f8 & (y3#2 <<< 19)
# int32#20 = 0x7f8 & (int32#27 <<< 19)
# 22 = 0x7f8 & (29 <<< 19)
rlwinm 22,29,19,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 185:   z1 ^= p21
# z1#3 = z1#2 ^ p21#2
# int32#16 = int32#7 ^ int32#25
# 18 = 9 ^ 27
xor 18,9,27
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 186: 

# input line 187:   p31 = *(uint32 *) (table1 + p31)
# p31#2 = *(int16 *) (table1 + p31)
# int32#22 = *(int16 *) (int32#5 + int32#20)
# 24 = *(int16 *) (7 + 22)
lwzx 24,7,22
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 188:   z0 ^= p22
# z0#3 = z0#2 ^ p22#2
# int32#7 = int32#3 ^ int32#26
# 9 = 5 ^ 28
xor 9,5,28
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 189:   p32 = 0x7f8 & (y3 <<< 27)
# p32 = 0x7f8 & (y3#2 <<< 27)
# int32#3 = 0x7f8 & (int32#27 <<< 27)
# 5 = 0x7f8 & (29 <<< 27)
rlwinm 5,29,27,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 190: 

# input line 191:   p32 = *(uint32 *) (table2 + p32)
# p32#2 = *(int16 *) (table2 + p32)
# int32#20 = *(int16 *) (int32#6 + int32#3)
# 22 = *(int16 *) (8 + 5)
lwzx 22,8,5
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 192:   z3 ^= p23
# z3#3 = z3#2 ^ p23#2
# int32#18 = int32#18 ^ int32#21
# 20 = 20 ^ 23
xor 20,20,23
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 193:   p33 = 0x7f8 & (y3 <<< 3)
# p33 = 0x7f8 & (y3#2 <<< 3)
# int32#21 = 0x7f8 & (int32#27 <<< 3)
# 23 = 0x7f8 & (29 <<< 3)
rlwinm 23,29,3,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 194: 

# input line 195:   e = *(uint32 *) (table0 + loop4)
# e#3 = *(int16 *) (table0 + loop4)
# int32#3 = *(int16 *) (int32#4 + int32#24)
# 5 = *(int16 *) (6 + 26)
lwzx 5,6,26
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 196:   loop4 += 4
# loop4 = loop4 + 4
# int32#24 = int32#24 + 4
# 26 = 26 + 4
addi 26,26,4
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 197: 

# input line 198:   p33 = *(uint32 *) (table3 + p33)
# p33#2 = *(int16 *) (table3 + p33)
# int32#21 = *(int16 *) (int32#2 + int32#21)
# 23 = *(int16 *) (4 + 23)
lwzx 23,4,23
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 199:   q0 = 0x7f8 & (x3 <<< 19)
# q0#3 = 0x7f8 & (x3 <<< 19)
# int32#25 = 0x7f8 & (int32#19 <<< 19)
# 27 = 0x7f8 & (21 <<< 19)
rlwinm 27,21,19,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 200: 

# input line 201:   q0 = *(uint32 *) (table2 + q0)
# q0#4 = *(int16 *) (table2 + q0#3)
# int32#27 = *(int16 *) (int32#6 + int32#25)
# 29 = *(int16 *) (8 + 27)
lwzx 29,8,27
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 202:   q1 = 0x7f8 & (x3 <<< 27)
# q1#3 = 0x7f8 & (x3 <<< 27)
# int32#25 = 0x7f8 & (int32#19 <<< 27)
# 27 = 0x7f8 & (21 <<< 27)
rlwinm 27,21,27,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 203:   lgeflags signed loop4 - 0
# flags signed loop4 - 0
# flags signed int32#24 - 0
# flags signed 26 - 0
cmpwi 26,-0
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 1

# input line 204: 

# input line 205:   q1 = *(uint32 *) (table3 + q1)
# q1#4 = *(int16 *) (table3 + q1#3)
# int32#28 = *(int16 *) (int32#2 + int32#25)
# 30 = *(int16 *) (4 + 27)
lwzx 30,4,27
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 1

# input line 206:   q2 = 0x7f8 & (x3 <<< 3)
# q2#3 = 0x7f8 & (x3 <<< 3)
# int32#25 = 0x7f8 & (int32#19 <<< 3)
# 27 = 0x7f8 & (21 <<< 3)
rlwinm 27,21,3,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 27
# live double values: 18
# live flags values: 1

# input line 207: 

# input line 208:   q2 = *(uint32 *) (table0 + q2)
# q2#4 = *(int16 *) (table0 + q2#3)
# int32#26 = *(int16 *) (int32#4 + int32#25)
# 28 = *(int16 *) (6 + 27)
lwzx 28,6,27
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 27
# live double values: 18
# live flags values: 1

# input line 209:   q3 = 0x7f8 & (x3 <<< 11)
# q3#3 = 0x7f8 & (x3 <<< 11)
# int32#25 = 0x7f8 & (int32#19 <<< 11)
# 27 = 0x7f8 & (21 <<< 11)
rlwinm 27,21,11,0x7f8
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 28
# live double values: 18
# live flags values: 1

# input line 210: 

# input line 211:   q3 = *(uint32 *) (table1 + q3)
# q3#4 = *(int16 *) (table1 + q3#3)
# int32#25 = *(int16 *) (int32#5 + int32#25)
# 27 = *(int16 *) (7 + 27)
lwzx 27,7,27
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 28
# live double values: 18
# live flags values: 1

# input line 212:   f = 0xff000000 & (q0 <<< 0)
# f = 0xff000000 & (q0#4 <<< 0)
# int32#29 = 0xff000000 & (int32#27 <<< 0)
# 31 = 0xff000000 & (29 <<< 0)
rlwinm 31,29,0,0xff000000
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 28
# live double values: 18
# live flags values: 1

# input line 213: 

# input line 214:   y3 = z3 ^ p30
# y3#2 = z3#3 ^ p30#2
# int32#27 = int32#18 ^ int32#23
# 29 = 20 ^ 25
xor 29,20,25
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 27
# live double values: 18
# live flags values: 1

# input line 215:   f bits 0xff0000 = q1 <<< 0
# f bits 0xff0000 = q1#4 <<< 0
# int32#29 bits 0xff0000 = int32#28 <<< 0
# 31 bits 0xff0000 = 30 <<< 0
rlwimi 31,30,0,0xff0000
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 1

# input line 216: 

# input line 217:   y2 = z2 ^ p31
# y2#2 = z2#3 ^ p31#2
# int32#23 = int32#17 ^ int32#22
# 25 = 19 ^ 24
xor 25,19,24
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 1

# input line 218:   f bits 0xff00 = q2 <<< 0
# f bits 0xff00 = q2#4 <<< 0
# int32#29 bits 0xff00 = int32#26 <<< 0
# 31 bits 0xff00 = 28 <<< 0
rlwimi 31,28,0,0xff00
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 1

# input line 219: 

# input line 220:   y1 = z1 ^ p32
# y1#2 = z1#3 ^ p32#2
# int32#22 = int32#16 ^ int32#20
# 24 = 18 ^ 22
xor 24,18,22
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 1

# input line 221:   f bits 0xff = q3 <<< 0
# f bits 0xff = q3#4 <<< 0
# int32#29 bits 0xff = int32#25 <<< 0
# 31 bits 0xff = 27 <<< 0
rlwimi 31,27,0,0xff
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 1

# input line 222: 

# input line 223:   y0 = z0 ^ p33
# y0#2 = z0#3 ^ p33#2
# int32#21 = int32#7 ^ int32#21
# 23 = 9 ^ 23
xor 23,9,23
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 1

# input line 224:   e ^= f
# e#2 = e#3 ^ f
# int32#3 = int32#3 ^ int32#29
# 5 = 5 ^ 31
xor 5,5,31
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 1

# input line 225: 

# input line 226: goto mainloop if !=
bne .label.mainloop

# input line 227:   

# input line 228:   x0 ^= e
# x0#2 = x0 ^ e#2
# int32#3 = int32#8 ^ int32#3
# 5 = 10 ^ 5
xor 5,10,5
# live mem32 values: 14
# live flag values: 0
# live mem64 values: 0
# live int32 values: 18
# live double values: 18
# live flags values: 0

# input line 229:   load callerint 18
# %caller_r18#2 = %caller_r18@stack
# int32#16 = mem32#1
# 18 = 128(1)
lwz 18,128(1)
# live mem32 values: 13
# live flag values: 0
# live mem64 values: 0
# live int32 values: 19
# live double values: 18
# live flags values: 0

# input line 230: 

# input line 231:   x1 ^= x0
# x1#2 = x1 ^ x0#2
# int32#7 = int32#9 ^ int32#3
# 9 = 11 ^ 5
xor 9,11,5
# live mem32 values: 13
# live flag values: 0
# live mem64 values: 0
# live int32 values: 19
# live double values: 18
# live flags values: 0

# input line 232:   load callerint 19
# %caller_r19#2 = %caller_r19@stack
# int32#17 = mem32#2
# 19 = 132(1)
lwz 19,132(1)
# live mem32 values: 12
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 233: 

# input line 234:   x2 ^= x1
# x2#2 = x2 ^ x1#2
# int32#8 = int32#10 ^ int32#7
# 10 = 12 ^ 9
xor 10,12,9
# live mem32 values: 12
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 235:   load callerint 20
# %caller_r20#2 = %caller_r20@stack
# int32#18 = mem32#3
# 20 = 136(1)
lwz 20,136(1)
# live mem32 values: 11
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 236: 

# input line 237:   x3 ^= x2
# x3#2 = x3 ^ x2#2
# int32#9 = int32#19 ^ int32#8
# 11 = 21 ^ 10
xor 11,21,10
# live mem32 values: 11
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 238:   load callerint 21
# %caller_r21#2 = %caller_r21@stack
# int32#19 = mem32#4
# 21 = 140(1)
lwz 21,140(1)
# live mem32 values: 10
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 239:   

# input line 240:   r00 = 0x7f8 & (y0 <<< 11)
# r00 = 0x7f8 & (y0#2 <<< 11)
# int32#10 = 0x7f8 & (int32#21 <<< 11)
# 12 = 0x7f8 & (23 <<< 11)
rlwinm 12,23,11,0x7f8
# live mem32 values: 10
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 241:   load callerint 22
# %caller_r22#2 = %caller_r22@stack
# int32#20 = mem32#5
# 22 = 144(1)
lwz 22,144(1)
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 242: 

# input line 243:   r00 = *(uint32 *) (table2 + r00)
# r00#2 = *(int16 *) (table2 + r00)
# int32#26 = *(int16 *) (int32#6 + int32#10)
# 28 = *(int16 *) (8 + 12)
lwzx 28,8,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 244:   r01 = 0x7f8 & (y0 <<< 19)
# r01 = 0x7f8 & (y0#2 <<< 19)
# int32#10 = 0x7f8 & (int32#21 <<< 19)
# 12 = 0x7f8 & (23 <<< 19)
rlwinm 12,23,19,0x7f8
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 245: 

# input line 246:   r01 = *(uint32 *) (table3 + r01)
# r01#2 = *(int16 *) (table3 + r01)
# int32#25 = *(int16 *) (int32#2 + int32#10)
# 27 = *(int16 *) (4 + 12)
lwzx 27,4,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 247:   r02 = 0x7f8 & (y0 <<< 27)
# r02 = 0x7f8 & (y0#2 <<< 27)
# int32#10 = 0x7f8 & (int32#21 <<< 27)
# 12 = 0x7f8 & (23 <<< 27)
rlwinm 12,23,27,0x7f8
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 248: 

# input line 249:   r02 = *(uint32 *) (table0 + r02)
# r02#2 = *(int16 *) (table0 + r02)
# int32#24 = *(int16 *) (int32#4 + int32#10)
# 26 = *(int16 *) (6 + 12)
lwzx 26,6,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 250:   r03 = 0x7f8 & (y0 <<< 3)
# r03 = 0x7f8 & (y0#2 <<< 3)
# int32#10 = 0x7f8 & (int32#21 <<< 3)
# 12 = 0x7f8 & (23 <<< 3)
rlwinm 12,23,3,0x7f8
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 251: 

# input line 252:   r03 = *(uint32 *) (table1 + r03)
# r03#2 = *(int16 *) (table1 + r03)
# int32#10 = *(int16 *) (int32#5 + int32#10)
# 12 = *(int16 *) (7 + 12)
lwzx 12,7,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 253:   r00 = 0xff000000 & (r00 <<< 0)
# r00#3 = 0xff000000 & (r00#2 <<< 0)
# int32#21 = 0xff000000 & (int32#26 <<< 0)
# 23 = 0xff000000 & (28 <<< 0)
rlwinm 23,28,0,0xff000000
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 254: 

# input line 255:   r01 = 0xff0000 & (r01 <<< 0)
# r01#3 = 0xff0000 & (r01#2 <<< 0)
# int32#25 = 0xff0000 & (int32#25 <<< 0)
# 27 = 0xff0000 & (27 <<< 0)
rlwinm 27,27,0,0xff0000
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 256:   v0 = x0 ^ r00
# v0 = x0#2 ^ r00#3
# int32#3 = int32#3 ^ int32#21
# 5 = 5 ^ 23
xor 5,5,23
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 257: 

# input line 258:   r02 = 0xff00 & (r02 <<< 0)
# r02#3 = 0xff00 & (r02#2 <<< 0)
# int32#21 = 0xff00 & (int32#24 <<< 0)
# 23 = 0xff00 & (26 <<< 0)
rlwinm 23,26,0,0xff00
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 259:   v3 = x3 ^ r01
# v3 = x3#2 ^ r01#3
# int32#9 = int32#9 ^ int32#25
# 11 = 11 ^ 27
xor 11,11,27
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 260: 

# input line 261:   r03 = 0xff & (r03 <<< 0)
# r03#3 = 0xff & (r03#2 <<< 0)
# int32#10 = 0xff & (int32#10 <<< 0)
# 12 = 0xff & (12 <<< 0)
rlwinm 12,12,0,0xff
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 262:   v2 = x2 ^ r02
# v2 = x2#2 ^ r02#3
# int32#8 = int32#8 ^ int32#21
# 10 = 10 ^ 23
xor 10,10,23
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 263: 

# input line 264:   r10 = 0x7f8 & (y1 <<< 11)
# r10 = 0x7f8 & (y1#2 <<< 11)
# int32#21 = 0x7f8 & (int32#22 <<< 11)
# 23 = 0x7f8 & (24 <<< 11)
rlwinm 23,24,11,0x7f8
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 265:   v1 = x1 ^ r03
# v1 = x1#2 ^ r03#3
# int32#7 = int32#7 ^ int32#10
# 9 = 9 ^ 12
xor 9,9,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 266:   

# input line 267:   r10 = *(uint32 *) (table2 + r10)
# r10#2 = *(int16 *) (table2 + r10)
# int32#25 = *(int16 *) (int32#6 + int32#21)
# 27 = *(int16 *) (8 + 23)
lwzx 27,8,23
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 268:   r11 = 0x7f8 & (y1 <<< 19)
# r11 = 0x7f8 & (y1#2 <<< 19)
# int32#10 = 0x7f8 & (int32#22 <<< 19)
# 12 = 0x7f8 & (24 <<< 19)
rlwinm 12,24,19,0x7f8
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 269: 

# input line 270:   r11 = *(uint32 *) (table3 + r11)
# r11#2 = *(int16 *) (table3 + r11)
# int32#24 = *(int16 *) (int32#2 + int32#10)
# 26 = *(int16 *) (4 + 12)
lwzx 26,4,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 271:   r12 = 0x7f8 & (y1 <<< 27)
# r12 = 0x7f8 & (y1#2 <<< 27)
# int32#10 = 0x7f8 & (int32#22 <<< 27)
# 12 = 0x7f8 & (24 <<< 27)
rlwinm 12,24,27,0x7f8
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 272: 

# input line 273:   r12 = *(uint32 *) (table0 + r12)
# r12#2 = *(int16 *) (table0 + r12)
# int32#21 = *(int16 *) (int32#4 + int32#10)
# 23 = *(int16 *) (6 + 12)
lwzx 23,6,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 274:   r13 = 0x7f8 & (y1 <<< 3)
# r13 = 0x7f8 & (y1#2 <<< 3)
# int32#10 = 0x7f8 & (int32#22 <<< 3)
# 12 = 0x7f8 & (24 <<< 3)
rlwinm 12,24,3,0x7f8
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 275: 

# input line 276:   r13 = *(uint32 *) (table1 + r13)
# r13#2 = *(int16 *) (table1 + r13)
# int32#10 = *(int16 *) (int32#5 + int32#10)
# 12 = *(int16 *) (7 + 12)
lwzx 12,7,12
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 277:   r10 = 0xff000000 & (r10 <<< 0)
# r10#3 = 0xff000000 & (r10#2 <<< 0)
# int32#25 = 0xff000000 & (int32#25 <<< 0)
# 27 = 0xff000000 & (27 <<< 0)
rlwinm 27,27,0,0xff000000
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 278: 

# input line 279:   r11 = 0xff0000 & (r11 <<< 0)
# r11#3 = 0xff0000 & (r11#2 <<< 0)
# int32#22 = 0xff0000 & (int32#24 <<< 0)
# 24 = 0xff0000 & (26 <<< 0)
rlwinm 24,26,0,0xff0000
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 280:   v1 ^= r10
# v1#2 = v1 ^ r10#3
# int32#7 = int32#7 ^ int32#25
# 9 = 9 ^ 27
xor 9,9,27
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 281: 

# input line 282:   r12 = 0xff00 & (r12 <<< 0)
# r12#3 = 0xff00 & (r12#2 <<< 0)
# int32#21 = 0xff00 & (int32#21 <<< 0)
# 23 = 0xff00 & (23 <<< 0)
rlwinm 23,23,0,0xff00
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 283:   v0 ^= r11
# v0#2 = v0 ^ r11#3
# int32#3 = int32#3 ^ int32#22
# 5 = 5 ^ 24
xor 5,5,24
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 284: 

# input line 285:   r13 = 0xff & (r13 <<< 0)
# r13#3 = 0xff & (r13#2 <<< 0)
# int32#22 = 0xff & (int32#10 <<< 0)
# 24 = 0xff & (12 <<< 0)
rlwinm 24,12,0,0xff
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 286:   v3 ^= r12
# v3#2 = v3 ^ r12#3
# int32#10 = int32#9 ^ int32#21
# 12 = 11 ^ 23
xor 12,11,23
# live mem32 values: 9
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 287:   load callerint 23
# %caller_r23#2 = %caller_r23@stack
# int32#21 = mem32#6
# 23 = 148(1)
lwz 23,148(1)
# live mem32 values: 8
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 288: 

# input line 289:   r20 = 0x7f8 & (y2 <<< 11)
# r20 = 0x7f8 & (y2#2 <<< 11)
# int32#9 = 0x7f8 & (int32#23 <<< 11)
# 11 = 0x7f8 & (25 <<< 11)
rlwinm 11,25,11,0x7f8
# live mem32 values: 8
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 290:   v2 ^= r13
# v2#2 = v2 ^ r13#3
# int32#8 = int32#8 ^ int32#22
# 10 = 10 ^ 24
xor 10,10,24
# live mem32 values: 8
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 291:   load callerint 24
# %caller_r24#2 = %caller_r24@stack
# int32#22 = mem32#7
# 24 = 152(1)
lwz 24,152(1)
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 292:   

# input line 293:   r20 = *(uint32 *) (table2 + r20)
# r20#2 = *(int16 *) (table2 + r20)
# int32#28 = *(int16 *) (int32#6 + int32#9)
# 30 = *(int16 *) (8 + 11)
lwzx 30,8,11
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 294:   r21 = 0x7f8 & (y2 <<< 19)
# r21 = 0x7f8 & (y2#2 <<< 19)
# int32#9 = 0x7f8 & (int32#23 <<< 19)
# 11 = 0x7f8 & (25 <<< 19)
rlwinm 11,25,19,0x7f8
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 295: 

# input line 296:   r21 = *(uint32 *) (table3 + r21)
# r21#2 = *(int16 *) (table3 + r21)
# int32#26 = *(int16 *) (int32#2 + int32#9)
# 28 = *(int16 *) (4 + 11)
lwzx 28,4,11
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 297:   r22 = 0x7f8 & (y2 <<< 27)
# r22 = 0x7f8 & (y2#2 <<< 27)
# int32#9 = 0x7f8 & (int32#23 <<< 27)
# 11 = 0x7f8 & (25 <<< 27)
rlwinm 11,25,27,0x7f8
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 298: 

# input line 299:   r22 = *(uint32 *) (table0 + r22)
# r22#2 = *(int16 *) (table0 + r22)
# int32#24 = *(int16 *) (int32#4 + int32#9)
# 26 = *(int16 *) (6 + 11)
lwzx 26,6,11
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 300:   r23 = 0x7f8 & (y2 <<< 3)
# r23 = 0x7f8 & (y2#2 <<< 3)
# int32#9 = 0x7f8 & (int32#23 <<< 3)
# 11 = 0x7f8 & (25 <<< 3)
rlwinm 11,25,3,0x7f8
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 301: 

# input line 302:   r23 = *(uint32 *) (table1 + r23)
# r23#2 = *(int16 *) (table1 + r23)
# int32#25 = *(int16 *) (int32#5 + int32#9)
# 27 = *(int16 *) (7 + 11)
lwzx 27,7,11
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 303:   r20 = 0xff000000 & (r20 <<< 0)
# r20#3 = 0xff000000 & (r20#2 <<< 0)
# int32#9 = 0xff000000 & (int32#28 <<< 0)
# 11 = 0xff000000 & (30 <<< 0)
rlwinm 11,30,0,0xff000000
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 304: 

# input line 305:   r21 = 0xff0000 & (r21 <<< 0)
# r21#3 = 0xff0000 & (r21#2 <<< 0)
# int32#26 = 0xff0000 & (int32#26 <<< 0)
# 28 = 0xff0000 & (28 <<< 0)
rlwinm 28,28,0,0xff0000
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 306:   v2 ^= r20
# v2#3 = v2#2 ^ r20#3
# int32#9 = int32#8 ^ int32#9
# 11 = 10 ^ 11
xor 11,10,11
# live mem32 values: 7
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 307:   load callerint 25
# %caller_r25#2 = %caller_r25@stack
# int32#23 = mem32#8
# 25 = 156(1)
lwz 25,156(1)
# live mem32 values: 6
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 308: 

# input line 309:   r22 = 0xff00 & (r22 <<< 0)
# r22#3 = 0xff00 & (r22#2 <<< 0)
# int32#28 = 0xff00 & (int32#24 <<< 0)
# 30 = 0xff00 & (26 <<< 0)
rlwinm 30,26,0,0xff00
# live mem32 values: 6
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 310:   v1 ^= r21
# v1#3 = v1#2 ^ r21#3
# int32#8 = int32#7 ^ int32#26
# 10 = 9 ^ 28
xor 10,9,28
# live mem32 values: 6
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 311:   load callerint 26
# %caller_r26#2 = %caller_r26@stack
# int32#24 = mem32#9
# 26 = 160(1)
lwz 26,160(1)
# live mem32 values: 5
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 312: 

# input line 313:   r23 = 0xff & (r23 <<< 0)
# r23#3 = 0xff & (r23#2 <<< 0)
# int32#26 = 0xff & (int32#25 <<< 0)
# 28 = 0xff & (27 <<< 0)
rlwinm 28,27,0,0xff
# live mem32 values: 5
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 314:   v0 ^= r22
# v0#3 = v0#2 ^ r22#3
# int32#7 = int32#3 ^ int32#28
# 9 = 5 ^ 30
xor 9,5,30
# live mem32 values: 5
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 315:   load callerint 27
# %caller_r27#2 = %caller_r27@stack
# int32#25 = mem32#10
# 27 = 164(1)
lwz 27,164(1)
# live mem32 values: 4
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 316: 

# input line 317:   r30 = 0x7f8 & (y3 <<< 11)
# r30 = 0x7f8 & (y3#2 <<< 11)
# int32#28 = 0x7f8 & (int32#27 <<< 11)
# 30 = 0x7f8 & (29 <<< 11)
rlwinm 30,29,11,0x7f8
# live mem32 values: 4
# live flag values: 0
# live mem64 values: 0
# live int32 values: 27
# live double values: 18
# live flags values: 0

# input line 318:   v3 ^= r23
# v3#3 = v3#2 ^ r23#3
# int32#3 = int32#10 ^ int32#26
# 5 = 12 ^ 28
xor 5,12,28
# live mem32 values: 4
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 319:   load callerint 28
# %caller_r28#2 = %caller_r28@stack
# int32#26 = mem32#11
# 28 = 168(1)
lwz 28,168(1)
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 27
# live double values: 18
# live flags values: 0

# input line 320:   

# input line 321:   r30 = *(uint32 *) (table2 + r30)
# r30#2 = *(int16 *) (table2 + r30)
# int32#28 = *(int16 *) (int32#6 + int32#28)
# 30 = *(int16 *) (8 + 30)
lwzx 30,8,30
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 322:   r31 = 0x7f8 & (y3 <<< 19)
# r31 = 0x7f8 & (y3#2 <<< 19)
# int32#6 = 0x7f8 & (int32#27 <<< 19)
# 8 = 0x7f8 & (29 <<< 19)
rlwinm 8,29,19,0x7f8
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 27
# live double values: 18
# live flags values: 0

# input line 323: 

# input line 324:   r31 = *(uint32 *) (table3 + r31)
# r31#2 = *(int16 *) (table3 + r31)
# int32#10 = *(int16 *) (int32#2 + int32#6)
# 12 = *(int16 *) (4 + 8)
lwzx 12,4,8
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 325:   r32 = 0x7f8 & (y3 <<< 27)
# r32 = 0x7f8 & (y3#2 <<< 27)
# int32#2 = 0x7f8 & (int32#27 <<< 27)
# 4 = 0x7f8 & (29 <<< 27)
rlwinm 4,29,27,0x7f8
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 27
# live double values: 18
# live flags values: 0

# input line 326: 

# input line 327:   r32 = *(uint32 *) (table0 + r32)
# r32#2 = *(int16 *) (table0 + r32)
# int32#6 = *(int16 *) (int32#4 + int32#2)
# 8 = *(int16 *) (6 + 4)
lwzx 8,6,4
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 328:   r33 = 0x7f8 & (y3 <<< 3)
# r33 = 0x7f8 & (y3#2 <<< 3)
# int32#2 = 0x7f8 & (int32#27 <<< 3)
# 4 = 0x7f8 & (29 <<< 3)
rlwinm 4,29,3,0x7f8
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 26
# live double values: 18
# live flags values: 0

# input line 329: 

# input line 330:   r33 = *(uint32 *) (table1 + r33)
# r33#2 = *(int16 *) (table1 + r33)
# int32#4 = *(int16 *) (int32#5 + int32#2)
# 6 = *(int16 *) (7 + 4)
lwzx 6,7,4
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 331:   r30 = 0xff000000 & (r30 <<< 0)
# r30#3 = 0xff000000 & (r30#2 <<< 0)
# int32#5 = 0xff000000 & (int32#28 <<< 0)
# 7 = 0xff000000 & (30 <<< 0)
rlwinm 7,30,0,0xff000000
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 332: 

# input line 333:   r31 = 0xff0000 & (r31 <<< 0)
# r31#3 = 0xff0000 & (r31#2 <<< 0)
# int32#2 = 0xff0000 & (int32#10 <<< 0)
# 4 = 0xff0000 & (12 <<< 0)
rlwinm 4,12,0,0xff0000
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 25
# live double values: 18
# live flags values: 0

# input line 334:   y3 = v3 ^ r30
# y3#3 = v3#3 ^ r30#3
# int32#3 = int32#3 ^ int32#5
# 5 = 5 ^ 7
xor 5,5,7
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 335: 

# input line 336:   r32 = 0xff00 & (r32 <<< 0)
# r32#3 = 0xff00 & (r32#2 <<< 0)
# int32#5 = 0xff00 & (int32#6 <<< 0)
# 7 = 0xff00 & (8 <<< 0)
rlwinm 7,8,0,0xff00
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 24
# live double values: 18
# live flags values: 0

# input line 337:   y2 = v2 ^ r31
# y2#3 = v2#3 ^ r31#3
# int32#2 = int32#9 ^ int32#2
# 4 = 11 ^ 4
xor 4,11,4
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 23
# live double values: 18
# live flags values: 0

# input line 338:   *(uint32 *) (out + 12) = y3
# *(uint32 *) (out + 12) = y3#3
# *(uint32 *) (int32#1 + 12) = int32#3
# *(uint32 *) (3 + 12) = 5
stw 5,12(3)
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 339: 

# input line 340:   r33 = 0xff & (r33 <<< 0)
# r33#3 = 0xff & (r33#2 <<< 0)
# int32#4 = 0xff & (int32#4 <<< 0)
# 6 = 0xff & (6 <<< 0)
rlwinm 6,6,0,0xff
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 22
# live double values: 18
# live flags values: 0

# input line 341:   y1 = v1 ^ r32
# y1#3 = v1#3 ^ r32#3
# int32#3 = int32#8 ^ int32#5
# 5 = 10 ^ 7
xor 5,10,7
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 21
# live double values: 18
# live flags values: 0

# input line 342:   *(uint32 *) (out + 8) = y2
# *(uint32 *) (out + 8) = y2#3
# *(uint32 *) (int32#1 + 8) = int32#2
# *(uint32 *) (3 + 8) = 4
stw 4,8(3)
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 20
# live double values: 18
# live flags values: 0

# input line 343: 

# input line 344:   y0 = v0 ^ r33
# y0#3 = v0#3 ^ r33#3
# int32#2 = int32#7 ^ int32#4
# 4 = 9 ^ 6
xor 4,9,6
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 19
# live double values: 18
# live flags values: 0

# input line 345:   *(uint32 *) (out + 4) = y1
# *(uint32 *) (out + 4) = y1#3
# *(uint32 *) (int32#1 + 4) = int32#3
# *(uint32 *) (3 + 4) = 5
stw 5,4(3)
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 18
# live double values: 18
# live flags values: 0

# input line 346: 

# input line 347:   *(uint32 *) (out + 0) = y0
# *(uint32 *) (out + 0) = y0#3
# *(uint32 *) (int32#1 + 0) = int32#2
# *(uint32 *) (3 + 0) = 4
stw 4,0(3)
# live mem32 values: 3
# live flag values: 0
# live mem64 values: 0
# live int32 values: 16
# live double values: 18
# live flags values: 0

# input line 348:   load callerint 29
# %caller_r29#2 = %caller_r29@stack
# int32#27 = mem32#12
# 29 = 172(1)
lwz 29,172(1)
# live mem32 values: 2
# live flag values: 0
# live mem64 values: 0
# live int32 values: 17
# live double values: 18
# live flags values: 0

# input line 349: 

# input line 350:   load callerint 30
# %caller_r30#2 = %caller_r30@stack
# int32#28 = mem32#13
# 30 = 176(1)
lwz 30,176(1)
# live mem32 values: 1
# live flag values: 0
# live mem64 values: 0
# live int32 values: 18
# live double values: 18
# live flags values: 0

# input line 351:   load callerint 31
# %caller_r31#2 = %caller_r31@stack
# int32#29 = mem32#14
# 31 = 180(1)
lwz 31,180(1)
# live mem32 values: 0
# live flag values: 0
# live mem64 values: 0
# live int32 values: 19
# live double values: 18
# live flags values: 0

# input line 352: 

# input line 353: leave
addi 1,1,192
blr
