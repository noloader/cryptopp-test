#-*- coding: utf-8 -*-

'''
 Copyright (c) 2016 NSR (National Security Research Institute)
 
 Permission is hereby granted, free of charge, to any person obtaining a copy 
 of this software and associated documentation files (the "Software"), to deal 
 in the Software without restriction, including without limitation the rights 
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 copies of the Software, and to permit persons to whom the Software is 
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in 
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 THE SOFTWARE.
'''

import struct

## LSH 추상 클래스
class LSHTemplate:

    _MASK = None
    _WORDBITLEN = None
    _NUMSTEP = None
    _BLOCKSIZE = 0
    _FORMAT_IN = None
    _FORMAT_OUT = None
    
    _outlenbits = 0
    _boff = None
    _cv = None
    _tcv = None
    _msg = None
    _buf = None
    
    _STEP = None
    _ALPHA_EVEN = None
    _ALPHA_ODD = None    
    _BETA_EVEN = None
    _BETA_ODD = None
    _GAMMA = None
    
    ## 생성자
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def __init__(self, outlenbits):
        self._init(outlenbits)
    
    
    ## HMAC 계산에 사용하기 위해서 내부 블록 길이 리턴
    #  @param [in] self 객체 포인터
    #  @return 내부 블록 길이
    def get_blocksize(self):
        return self._BLOCKSIZE
    
        
    ## 메시지 확장 함수
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 인덱스
    def _msg_expansion(self, data, offset):
        block = bytearray(data[offset:offset + self._BLOCKSIZE])
        self._msg[0:32] = struct.unpack(self._FORMAT_IN, block[0:self._BLOCKSIZE])
        
        for i in range(2, self._NUMSTEP + 1):
            idx = 16 * i
            self._msg[idx     ] = (self._msg[idx - 16] + self._msg[idx - 29]) & self._MASK
            self._msg[idx +  1] = (self._msg[idx - 15] + self._msg[idx - 30]) & self._MASK
            self._msg[idx +  2] = (self._msg[idx - 14] + self._msg[idx - 32]) & self._MASK
            self._msg[idx +  3] = (self._msg[idx - 13] + self._msg[idx - 31]) & self._MASK
            self._msg[idx +  4] = (self._msg[idx - 12] + self._msg[idx - 25]) & self._MASK
            self._msg[idx +  5] = (self._msg[idx - 11] + self._msg[idx - 28]) & self._MASK
            self._msg[idx +  6] = (self._msg[idx - 10] + self._msg[idx - 27]) & self._MASK
            self._msg[idx +  7] = (self._msg[idx -  9] + self._msg[idx - 26]) & self._MASK
            self._msg[idx +  8] = (self._msg[idx -  8] + self._msg[idx - 21]) & self._MASK
            self._msg[idx +  9] = (self._msg[idx -  7] + self._msg[idx - 22]) & self._MASK
            self._msg[idx + 10] = (self._msg[idx -  6] + self._msg[idx - 24]) & self._MASK
            self._msg[idx + 11] = (self._msg[idx -  5] + self._msg[idx - 23]) & self._MASK
            self._msg[idx + 12] = (self._msg[idx -  4] + self._msg[idx - 17]) & self._MASK
            self._msg[idx + 13] = (self._msg[idx -  3] + self._msg[idx - 20]) & self._MASK
            self._msg[idx + 14] = (self._msg[idx -  2] + self._msg[idx - 19]) & self._MASK
            self._msg[idx + 15] = (self._msg[idx -  1] + self._msg[idx - 18]) & self._MASK
            
    ## 워드 단위 순환 함수
    #  @param [in] self 객체 포인터
    def _word_permutation(self):
        self._cv[ 0] = self._tcv[ 6]
        self._cv[ 1] = self._tcv[ 4]
        self._cv[ 2] = self._tcv[ 5]
        self._cv[ 3] = self._tcv[ 7]
        self._cv[ 4] = self._tcv[12]
        self._cv[ 5] = self._tcv[15]
        self._cv[ 6] = self._tcv[14]
        self._cv[ 7] = self._tcv[13]
        self._cv[ 8] = self._tcv[ 2]
        self._cv[ 9] = self._tcv[ 0]
        self._cv[10] = self._tcv[ 1]
        self._cv[11] = self._tcv[ 3]
        self._cv[12] = self._tcv[ 8]
        self._cv[13] = self._tcv[11]
        self._cv[14] = self._tcv[10]
        self._cv[15] = self._tcv[ 9]
        
    ## 스텝 함수 - LSH를 상속받는 클래스에서 별도로 구현해야 함
    #  @param [in] self 객체 포인터
    #  @param [in] idx 스텝 인덱스
    #  @param [in] alpha 회전값 알파
    #  @param [in] beta 회전값 베타
    def _step(self, idx, alpha, beta):
        raise NotImplementedError("Implement this method")
    
    ## 압축 함수
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 인덱스
    def _compress(self, data, offset = 0):    
        
        self._msg_expansion(data, offset)
        
        for idx in range(int(self._NUMSTEP / 2)):
            self._step(2 * idx, self._ALPHA_EVEN, self._BETA_EVEN)
            self._step(2 * idx + 1, self._ALPHA_ODD, self._BETA_ODD)
        
        for idx in range(16):
            self._cv[idx] ^= self._msg[16 * self._NUMSTEP + idx]

    
    ## IV 생성 함수 - LSH를 상속받는 클래스에서 별도로 구현해야 함
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def _init_iv(self, outlenbits):
        raise NotImplementedError("Implement this method")
    
    def _init(self, outlenbits):
        self._boff = 0
        self._tcv = [0] * 16
        self._msg = [0] * (16 * (self._NUMSTEP + 1))
        self._buf = [0] * self._BLOCKSIZE
        self._init_iv(outlenbits)
    
    ## 리셋 함수 - 키 입력 직후의 상태로 되돌린다
    #  @param self 객체 포인터
    def reset(self):
        self._init(self._outlenbits)
    
    
    ## 업데이트 함수
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    def update(self, data, offset = 0, length = -1):
        if data is None or len(data) == 0 or length == 0:
            return
        
        if length == -1:
            length = (len(data) - offset) << 3
        
        len_bytes = length >> 3
        len_bits = length & 0x7
        
        rbytes = self._boff >> 3
        rbits = self._boff & 0x7
        
        if rbits > 0:
            raise AssertionError("bit level update is not allowed")
        
        gap = self._BLOCKSIZE - rbytes
        
        if len_bytes >= gap:
            self._buf[rbytes:self._BLOCKSIZE] = data[offset:offset + gap]
            self._compress(self._buf)
            self._boff = 0
            offset += gap
            len_bytes -= gap
        
        while len_bytes >= self._BLOCKSIZE:
            self._compress(data, offset)            
            offset += self._BLOCKSIZE
            len_bytes -= self._BLOCKSIZE
        
        if len_bytes > 0:
            self._buf[rbytes:rbytes + len_bytes] = data[offset:offset + len_bytes]
            self._boff += len_bytes << 3
            offset += len_bytes
        
        if len_bits > 0:
            self._buf[len_bytes] = data[offset] & ((0xff >> len_bits) ^ 0xff)
            self._boff += len_bits
    
    ## 종료 함수 - 최종 해쉬 값을 계산하여 리턴한다
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    #  @return 계산된 해쉬값
    def final(self, data = None, offset = 0, length = -1):
        if data is not None:
            self.update(data, offset, length)
        
        rbytes = self._boff >> 3
        rbits = self._boff & 0x7
        
        if rbits > 0:
            self._buf[rbytes] |= (0x1 << (7 - rbits))
        else:
            self._buf[rbytes] = 0x80
        
        pos = rbytes + 1
        if (pos < self._BLOCKSIZE):
            self._buf[pos:] = [0] * (self._BLOCKSIZE - pos)
            
        self._compress(self._buf)
        
        temp = [0] * 8
        for idx in range(8):
            temp[idx] = (self._cv[idx] ^ self._cv[idx + 8]) & self._MASK
        
        self._init(self._outlenbits)
        
        rbytes = self._outlenbits >> 3
        rbits = self._outlenbits & 0x7
        if rbits > 0:
            rbytes += 1
        
        result = bytearray(struct.pack(self._FORMAT_OUT, temp[0], temp[1], temp[2], temp[3], temp[4], temp[5], temp[6], temp[7]))
        result = result[0:rbytes]
        if rbits > 0:
            result[rbytes - 1] &= (0xff << (8 - rbits))
        
        return result
