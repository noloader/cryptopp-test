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

from .lsh_digest import LSHDigest

## HMAC 구현 클래스
class HmacLSH:
    
    __IPAD = 0x36
    __OPAD = 0x5c

    #__md = None
    __blocksize = 0
    __i_key_pad = None
    __o_key_pad = None
    __outlenbits = 0

    
    ## 생성자
    #  @param [in] self 객체 포인터
    #  @param [in] wordlenbits 워드 길이 256, 512 중 하나여야 함
    #  @param [in] outlenbits 출력 해시 길이 1 ~ wordlenbits 사이의 값이어야 함
    def __init__(self, wordlenbits, outlenbits = 0):
        self.__outlenbits = outlenbits
        if outlenbits > 0:
            self.__md = LSHDigest.getInstance(wordlenbits, outlenbits)
        else:
            self.__md = LSHDigest.getInstance(wordlenbits)
        self.__blocksize = self.__md.get_blocksize()
    
    ## HMAC 계산을 위한 초기화
    #  @param [in] self 객체 포인터
    #  @param [in] key 키
    def init(self, key):

        if key is None:
            key = bytearray([0] * self._blocksize)
            
        if len(key) > self.__blocksize:
            self.__md.reset()
            key = self.__md.final(key)
        
        self.__i_key_pad = [HmacLSH.__IPAD] * self.__blocksize
        self.__o_key_pad = [HmacLSH.__OPAD] * self.__blocksize
        
        for idx in range(len(key)):
            self.__i_key_pad[idx] ^= key[idx]
            self.__o_key_pad[idx] ^= key[idx]

        self.reset()
    
    
    ## 새로운 HMAC을 계산할 수 있도록 객체를 초기화한다
    #  @param [in] self 객체 포인터
    def reset(self):
        self.__md.reset()
        self.__md.update(self.__i_key_pad)
    
    
    ## HMAC을 계산할 메시지를 추가한다.
    #  @param [in] self 객체 포인터
    #  @param [in] msg 입력 메시지
    def update(self, msg):
        if msg is None:
            return
        self.__md.update(msg)
    
    
    ## HMAC을 계산하고 결과를 리턴한다.
    #  @param [in] self 객체 포인터
    #  @return 계산된 HMAC 값
    def final(self):
        result = self.__md.final()
        self.__md.update(self.__o_key_pad)
        self.__md.update(result)
        result = self.__md.final()
        self.reset()
        return result
        
    ## digest 함수 - 최종 해쉬값을 계산하여 리턴한다.
    #  @param [in] wordlenbits 워드 길이 256, 512 중 하나여야 함
    #  @param [in] outlenbits 출력 해시 길이 1 ~ wordlenbits 사이의 값이어야 함
    #  @param [in] key HMAC key
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    #  @return 계산된 HMAC값
    @staticmethod
    def digest(wordlenbits, outlenbits = None, key = None, data = None, offset = 0, length = -1):
        hmac = HmacLSH(wordlenbits, outlenbits)
        hmac.init(key)
        hmac.update(data, offset, length)
        return hmac.final()

