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

from .lsh256 import LSH256
from .lsh512 import LSH512

## 해쉬 함수 wrapper 클래스
class LSHDigest:

    ## 파라미터에 맞는 LSH 알고리즘 객체 생성
    #  @param [in] wordlenbits 워드 길이 (비트) 256, 512만 가능함
    #  @param [in] outlenbits 출력 길이 (비트) 1 ~ 256 (LSH-256) 혹은 1 ~ 512 (LSH-512) 가 가능함
    #  @return LSH 객체
    @staticmethod
    def getInstance(wordlenbits, outlenbits = None):
        if outlenbits is None:
            outlenbits = wordlenbits
        
        if wordlenbits == 256:            
            return LSH256(outlenbits)
        
        elif wordlenbits == 512:            
            return LSH512(outlenbits)
        
        else:
            raise ValueError("Unsupported algorithm parameter");


    ## digest 함수 - 최종 해쉬값을 계산하여 리턴한다.
    #  @param [in] wordlenbits 워드 길이 256, 512 중 하나여야 함
    #  @param [in] outlenbits 출력 해시 길이 1 ~ wordlenbits 사이의 값이어야 함
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    #  @return 계산된 해쉬값
    @staticmethod
    def digest(wordlenbits, outlenbits = None, data = None, offset = 0, length = -1):
        if outlenbits is None:
            outlenbits = wordlenbits
        
        lsh = LSHDigest.getInstance(wordlenbits, outlenbits)
        return lsh.final(data, offset, length)